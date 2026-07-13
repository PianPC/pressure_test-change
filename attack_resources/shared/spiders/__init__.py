from __future__ import annotations

from .ipdeny_spider import IPDenySpider
from .shodan_spider import ShodanSpider
from .fofa_spider import FOFASpider
from .sonar_spider import SonarSpider

SPIDERS = {
    "ipdeny": IPDenySpider(),
    "shodan": ShodanSpider(),
    "fofa": FOFASpider(),
    "sonar": SonarSpider(),
}


def get_spider(name: str):
    if name not in SPIDERS:
        raise ValueError(f"Unknown spider: {name}")
    return SPIDERS[name]


__all__ = ["SPIDERS", "IPDenySpider", "ShodanSpider", "FOFASpider", "SonarSpider", "get_spider"]