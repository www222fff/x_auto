# x_auto
auto send twitter msg

curl -X POST "https://bitcoin-monitor-x-auto.feng73440.workers.dev/tweet" -H "Content-Type: application/json" -d '{"text":"Hello"}'
dannyaw@N-5CG2160L1X:~/x_auto$ curl -X POST "https://bitcoin-monitor-x-auto.feng73440.workers.dev/tweet" -H "Content-Type: application/json" -d '{"text":"Hello"}'
{
  "error": "Create tweet failed",
  "status": 403,
  "data": {
    "title": "Forbidden",
    "type": "about:blank",
    "status": 403,
    "detail": "Forbidden"
  }
}

Does not work, n8n works well with same X app, no idea?
