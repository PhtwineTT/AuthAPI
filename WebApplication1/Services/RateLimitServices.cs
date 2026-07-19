using System.Collections.Concurrent;
namespace AuthAPI.Services
{
    public class RateLimitServices
    {
        private readonly ConcurrentDictionary<string, ConcurrentQueue<DateTime>> _requestLogs = new();
        public bool IsAllowed (string cilentIp, int maxRequest, TimeSpan timeWindows )
        {
            var now = DateTime.UtcNow; 
            var requestQueue = _requestLogs.GetOrAdd(cilentIp, new ConcurrentQueue<DateTime>());
            while (requestQueue.TryPeek(out var oldestRequest) && (now -  oldestRequest)> timeWindows)
            {
                requestQueue.TryDequeue(out _);
            }
            if (requestQueue.Count < maxRequest)
            {
                requestQueue.Enqueue(now);
                return true;
            }
            return false;
        }
    }
}
