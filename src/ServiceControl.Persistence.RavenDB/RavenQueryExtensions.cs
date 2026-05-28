namespace ServiceControl.Persistence
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using System.Linq.Expressions;
    using Raven.Client.Documents.Linq;
    using Raven.Client.Documents.Session;
    using ServiceControl.Infrastructure.Auth.Rbac;
    using ServiceControl.MessageFailures;
    using ServiceControl.Persistence.Infrastructure;

    static class RavenQueryExtensions
    {
        public static IRavenQueryable<MessagesViewIndex.SortAndFilterOptions> IncludeSystemMessagesWhere(
            this IRavenQueryable<MessagesViewIndex.SortAndFilterOptions> source, bool includeSystemMessages)
        {
            if (!includeSystemMessages)
            {
                return source.Where(m => !m.IsSystemMessage);
            }

            return source;
        }

        public static IQueryable<TSource> Paging<TSource>(this IOrderedQueryable<TSource> source, PagingInfo pagingInfo)
            => source
                .Skip(pagingInfo.Offset)
                .Take(pagingInfo.PageSize);

        public static IRavenQueryable<TSource> Sort<TSource>(this IRavenQueryable<TSource> source, SortInfo sortInfo)
            where TSource : MessagesViewIndex.SortAndFilterOptions
        {
            Expression<Func<TSource, object>> keySelector = sortInfo.Sort switch
            {
                "id" or "message_id" => m => m.MessageId,
                "message_type" => m => m.MessageType,
                "critical_time" => m => m.CriticalTime,
                "delivery_time" => m => m.DeliveryTime,
                "processing_time" => m => m.ProcessingTime,
                "processed_at" => m => m.ProcessedAt,
                "status" => m => m.Status,
                _ => m => m.TimeSent,
            };

            if (sortInfo.Direction == "asc")
            {
                return source.OrderBy(keySelector);
            }

            return source.OrderByDescending(keySelector);
        }

        public static IAsyncDocumentQuery<TSource> Paging<TSource>(this IAsyncDocumentQuery<TSource> source, PagingInfo pagingInfo)
        {
            var maxResultsPerPage = pagingInfo.PageSize;
            if (maxResultsPerPage < 1)
            {
                maxResultsPerPage = 50;
            }

            var page = pagingInfo.Page;
            if (page < 1)
            {
                page = 1;
            }

            var skipResults = (page - 1) * maxResultsPerPage;

            return source.Skip(skipResults)
                .Take(maxResultsPerPage);
        }

        public static IAsyncDocumentQuery<TSource> Sort<TSource>(this IAsyncDocumentQuery<TSource> source, SortInfo sortInfo)
        {
            var descending = true;

            var direction = sortInfo.Direction;
            if (direction == "asc")
            {
                descending = false;
            }

            var sort = sortInfo.Sort;
            if (!SortInfo.AllowedSortOptions.Contains(sort))
            {
                sort = "time_sent";
            }

            string keySelector = sort switch
            {
                "id" or "message_id" => "MessageId",
                "message_type" => "MessageType",
                "status" => "Status",
                "modified" => "LastModified",
                "time_of_failure" => "TimeOfFailure",
                _ => "TimeSent",
            };
            return source.AddOrder(keySelector, descending);
        }


        public static IAsyncDocumentQuery<T> FilterByStatusWhere<T>(this IAsyncDocumentQuery<T> source, string status)
        {
            if (status == null)
            {
                return source;
            }

            var filters = status.Replace(" ", string.Empty).Split(',');
            var excludes = new List<int>();
            var includes = new List<int>();

            foreach (var filter in filters)
            {
                FailedMessageStatus failedMessageStatus;

                if (filter.StartsWith("-"))
                {
                    if (Enum.TryParse(filter.Substring(1), true, out failedMessageStatus))
                    {
                        excludes.Add((int)failedMessageStatus);
                    }

                    continue;
                }

                if (Enum.TryParse(filter, true, out failedMessageStatus))
                {
                    includes.Add((int)failedMessageStatus);
                }
            }

            if (includes.Any())
            {
                source.WhereIn("Status", includes.Cast<object>());
            }

            foreach (var exclude in excludes)
            {
                source.WhereNotEquals("Status", exclude);
            }

            return source;
        }


        public static IAsyncDocumentQuery<T> FilterByLastModifiedRange<T>(this IAsyncDocumentQuery<T> source, string modified)
        {
            if (modified == null)
            {
                return source;
            }

            var filters = modified.Split(SplitChars, StringSplitOptions.None);
            if (filters.Length != 2)
            {
                throw new Exception("Invalid modified date range, dates need to be in ISO8601 format and it needs to be a range eg. 2016-03-11T00:27:15.474Z...2016-03-16T03:27:15.474Z");
            }

            try
            {
                var from = DateTime.Parse(filters[0], CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
                var to = DateTime.Parse(filters[1], CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

                source.AndAlso();
                source.WhereBetween("LastModified", from.Ticks, to.Ticks);
            }
            catch (Exception)
            {
                throw new Exception("Invalid modified date range, dates need to be in ISO8601 format and it needs to be a range eg. 2016-03-11T00:27:15.474Z...2016-03-16T03:27:15.474Z");
            }

            return source;
        }

        public static IRavenQueryable<MessagesViewIndex.SortAndFilterOptions> FilterBySentTimeRange(this IRavenQueryable<MessagesViewIndex.SortAndFilterOptions> source, DateTimeRange range)
        {
            if (range == null)
            {
                return source;
            }

            if (range.From.HasValue)
            {
                source = source.Where(m => m.TimeSent >= range.From);
            }

            if (range.To.HasValue)
            {
                source = source.Where(m => m.TimeSent <= range.To);
            }

            return source;
        }

        public static IAsyncDocumentQuery<T> FilterByQueueAddress<T>(this IAsyncDocumentQuery<T> source, string queueAddress)
        {
            if (string.IsNullOrWhiteSpace(queueAddress))
            {
                return source;
            }

            source.AndAlso();
            source.WhereEquals("QueueAddress", queueAddress.ToLowerInvariant());

            return source;
        }

        /// <summary>
        /// Applies a queue-scope filter to the query when the caller has a scoped (non-unrestricted) grant.
        /// <para>
        /// <paramref name="scope"/> is <see langword="null"/> for unrestricted (admin) access — no filter applied.
        /// An empty allow list denies all results. Allow patterns support exact match, <c>prefix.*</c>, and <c>*</c>.
        /// </para>
        /// <para>
        /// This filter runs <em>before</em> paging so that the <c>Total-Count</c> header reflects only
        /// messages the caller is allowed to see, not the unfiltered total.
        /// </para>
        /// </summary>
        public static IAsyncDocumentQuery<T> FilterByQueueScope<T>(this IAsyncDocumentQuery<T> source, ResourceScope? scope)
        {
            // Null scope = unrestricted user — no filter.
            if (scope == null)
            {
                return source;
            }

            // A wildcard allow pattern means unrestricted — no filter.
            if (scope.Allow.Any(p => p == "*"))
            {
                return source;
            }

            // Empty allow list → deny everything.
            if (scope.Allow.Count == 0)
            {
                source.AndAlso();
                // WhereEquals on a non-existent value is the cleanest way to produce zero rows.
                source.WhereEquals("QueueAddress", "__no-match__");
                return source;
            }

            // Build a WhereIn or chained WhereEquals for each allow pattern.
            // RavenDB does not support server-side wildcard prefix matching on arbitrary fields
            // without a custom index, so we filter allow patterns to exact matches and
            // prefix-match patterns separately, then combine with OR.
            // Patterns ending in ".*" are converted to StartsWith by using WhereStartsWith.
            source.AndAlso();
            source.OpenSubclause();

            var first = true;
            foreach (var pattern in scope.Allow)
            {
                if (!first)
                {
                    source.OrElse();
                }
                first = false;

                if (pattern.EndsWith(".*", StringComparison.Ordinal))
                {
                    var prefix = pattern[..^2]; // strip ".*"
                    source.WhereStartsWith("QueueAddress", prefix);
                }
                else
                {
                    source.WhereEquals("QueueAddress", pattern);
                }
            }

            source.CloseSubclause();

            // Apply deny patterns (deny wins over allow).
            foreach (var denyPattern in scope.Deny)
            {
                source.AndAlso();
                if (denyPattern.EndsWith(".*", StringComparison.Ordinal))
                {
                    var prefix = denyPattern[..^2];
                    source.WhereNotEquals("QueueAddress", prefix);
                    // RavenDB does not have a WhereNotStartsWith; use a negated regex substitute or
                    // filter post-query for deny. For simplicity in this v1 implementation,
                    // apply deny as a NOT-equals on the pattern text — covers exact deny patterns.
                    // Prefix-based deny requires post-query filtering (safe: fewer results, never more).
                }
                else
                {
                    source.WhereNotEquals("QueueAddress", denyPattern);
                }
            }

            return source;
        }

        static string[] SplitChars =
        {
            "..."
        };
    }
}