import asyncio

from collector.agent.manager import AgentManager
from collector.core import configure_logging, configure_tracing
from collector.core.config import load_config


async def run() -> None:
    config = load_config()
    configure_logging(config.log_level)
    configure_tracing(config.collector_name)
    manager = AgentManager(config)
    await manager.run()


if __name__ == "__main__":
    asyncio.run(run())
