"""Run the BreachScope API server."""
import uvicorn
from breachscope.core.config import settings

if __name__ == "__main__":
    uvicorn.run(
        "breachscope.api.server:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True,
    )
