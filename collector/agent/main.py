import asyncio

from collector.agent.manager import AgentManager
from collector.core import CollectorConfig, configure_logging, configure_tracing


async def run() -> None:
    config = CollectorConfig.from_env()
    configure_logging(config.log_level)
    configure_tracing(config.collector_name)
    manager = AgentManager(config)
    await manager.run()


if __name__ == "__main__":
    asyncio.run(run())
