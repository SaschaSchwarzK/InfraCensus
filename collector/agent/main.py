import asyncio

from collector.agent.manager import AgentManager
from collector.core import CollectorConfig, configure_logging


async def run() -> None:
    config = CollectorConfig.from_env()
    configure_logging(config.log_level)
    manager = AgentManager(config)
    await manager.run()


if __name__ == "__main__":
    asyncio.run(run())
