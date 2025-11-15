import aiohttp
from typing import Dict, List
from urllib.parse import urlparse, parse_qs
import config  # novo

class HTTPClient:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session: aiohttp.ClientSession | None = None
        self.headers = {
            "User-Agent": config.DEFAULT_USER_AGENT,
        }

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(headers=self.headers)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.session:
            await self.session.close()

    async def get(self, url: str, params: Dict[str, str] | None = None):
        assert self.session is not None
        async with self.session.get(
            url,
            params=params,
            timeout=config.DEFAULT_TIMEOUT,  # usando config
        ) as resp:
            text = await resp.text(errors="ignore")
            headers = dict(resp.headers)
            return type(
                "Response",
                (),
                {
                    "status": resp.status,
                    "text": text,
                    "headers": headers,
                },
            )

    async def discover_get_params(self, url: str) -> List[str]:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        return list(qs.keys())
