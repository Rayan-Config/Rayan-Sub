from typing import Dict, List
from datetime import datetime
import re
from urllib.parse import urlparse

class ChannelMetrics:
    """
    Class to store and track metrics for each proxy config channel.
    All metrics start with default values of 0 or None.
    """
    def __init__(self):
        self.total_configs = 0          # Total number of configs found in channel (default: 0)
        self.valid_configs = 0          # Number of valid configs after validation (default: 0)
        self.unique_configs = 0         # Number of unique configs (not duplicates) (default: 0)
        self.avg_response_time = 0      # Average response time in seconds (default: 0)
        self.last_success_time = None   # Timestamp of last successful fetch (default: None)
        self.fail_count = 0             # Number of failed fetch attempts (default: 0)
        self.success_count = 0          # Number of successful fetch attempts (default: 0)
        self.overall_score = 0.0        # Overall channel performance score 0-100 (default: 0.0)
        self.protocol_counts = {}       # Count of configs per protocol (default: empty dict)

class ChannelConfig:
    """
    Class to store channel configuration and associated metrics.
    Default state for each channel is enabled (True).
    """
    def __init__(self, url: str, enabled: bool = True):
        self.url = url
        self.enabled = enabled
        self.metrics = ChannelMetrics()
        # Check if channel is a Telegram channel by URL pattern
        self.is_telegram = bool(re.match(r'^https://t\.me/s/', url))
        
    def calculate_overall_score(self):
        """
        Calculate overall channel score based on multiple factors:
        - Reliability (35%): Success rate of fetch attempts
        - Quality (25%): Ratio of valid configs to total configs
        - Uniqueness (25%): Ratio of unique configs to valid configs
        - Response Time (15%): Score based on average response time
        
        Total score ranges from 0 to 100. Channel is disabled if score falls below 25.
        """
        reliability_score = (self.metrics.success_count / (self.metrics.success_count + self.metrics.fail_count)) * 35 if (self.metrics.success_count + self.metrics.fail_count) > 0 else 0
        quality_score = (self.metrics.valid_configs / self.metrics.total_configs) * 25 if self.metrics.total_configs > 0 else 0
        uniqueness_score = (self.metrics.unique_configs / self.metrics.valid_configs) * 25 if self.metrics.valid_configs > 0 else 0
        response_score = max(0, min(15, 15 * (1 - (self.metrics.avg_response_time / 10)))) if self.metrics.avg_response_time > 0 else 15
        
        self.metrics.overall_score = reliability_score + quality_score + uniqueness_score + response_score

class ProxyConfig:
    def __init__(self):
        # List of source URLs to fetch proxy configs from
        # Add or remove channels here. Each ChannelConfig takes a URL and enabled status (default: True)
        initial_urls = [
            ChannelConfig("https://Rayan-Config.github.io/ALL"),
            ChannelConfig("https://raw.githubusercontent.com/4n0nymou3/ss-config-updater/refs/heads/main/configs.txt"),
            ChannelConfig("https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt"),
            ChannelConfig("https://t.me/s/Rayan_Proxy_Hub_I"),
            ChannelConfig("https://t.me/s/Rayan_Proxy_Hub_II")
        ]

        # Remove duplicate URLs before assigning to SOURCE_URLS
        self.SOURCE_URLS = self._remove_duplicate_urls(initial_urls)

        # Global limits for number of configs per protocol
        # Default values: min=3, max=25
        # Adjust these values to control how many configs of each type are collected
        self.PROTOCOL_CONFIG_LIMITS = {
            "min": 15,    # Minimum configs required per protocol (default: 3)
            "max": 250    # Maximum configs allowed per protocol (default: 25)
        }

        # Supported proxy protocols configuration
        # For each protocol:
        # - min_configs: Minimum number of configs required (default: 3)
        # - max_configs: Maximum number of configs allowed (default: 25)
        # - priority: Higher priority means more configs kept during balancing (default: 1, high priority: 2)
        # - flexible_max: If True, max_configs can be dynamically adjusted (default: True)
        # - aliases: Alternative protocol prefixes to recognize (optional)
        self.SUPPORTED_PROTOCOLS: Dict[str, Dict] = {
            "wireguard://": {
                "min_configs": self.PROTOCOL_CONFIG_LIMITS["min"],
                "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"],
                "priority": 2,
                "flexible_max": True
            },
            "hysteria2://": {
                "min_configs": self.PROTOCOL_CONFIG_LIMITS["min"],
                "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"],
                "priority": 1,
                "flexible_max": True,
                "aliases": ["hy2://"]
            },
            "vless://": {
                "min_configs": self.PROTOCOL_CONFIG_LIMITS["min"],
                "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"],
                "priority": 2,
                "flexible_max": True
            },
            "vmess://": {
                "min_configs": self.PROTOCOL_CONFIG_LIMITS["min"],
                "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"],
                "priority": 1,
                "flexible_max": True
            },
            "ss://": {
                "min_configs": self.PROTOCOL_CONFIG_LIMITS["min"],
                "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"],
                "priority": 1,
                "flexible_max": True
            },
            "trojan://": {
                "min_configs": self.PROTOCOL_CONFIG_LIMITS["min"],
                "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"],
                "priority": 2,
                "flexible_max": True
            },
            "tuic://": {
                "min_configs": self.PROTOCOL_CONFIG_LIMITS["min"],
                "max_configs": self.PROTOCOL_CONFIG_LIMITS["max"],
                "priority": 1,
                "flexible_max": True
            }
        }

        # Channel-specific configuration limits
        self.MIN_CONFIGS_PER_CHANNEL = 1     # Minimum configs required from each channel (default: 3)
        self.MAX_CONFIGS_PER_CHANNEL = 100    # Maximum configs allowed from each channel (default: 50)
        self.MAX_CONFIG_AGE_DAYS = 90        # Maximum age of configs in days (default: 90)
        self.CHANNEL_RETRY_LIMIT = 10        # Maximum retry attempts per channel (default: 10)
        self.CHANNEL_ERROR_THRESHOLD = 0.7   # Error rate threshold to disable channel (default: 0.7 or 70%)
        self.MIN_PROTOCOL_RATIO = 0.1        # Minimum ratio of configs per protocol (default: 0.1 or 10%)

        # Dynamic protocol adjustment settings
        self.DYNAMIC_PROTOCOL_ADJUSTMENT = True   # Enable/disable dynamic adjustment (default: True)
        self.PROTOCOL_BALANCE_FACTOR = 1.5        # Factor for adjusting protocol limits (default: 1.5)

        # Output file paths (default paths shown)
        self.OUTPUT_FILE = 'configs/proxy_configs.txt'    # Path to save final configs
        self.STATS_FILE = 'configs/channel_stats.json'    # Path to save channel stats
        
        # HTTP request settings
        self.MAX_RETRIES = 10            # Maximum number of retry attempts (default: 10)
        self.RETRY_DELAY = 15            # Delay between retries in seconds (default: 15)
        self.REQUEST_TIMEOUT = 90        # Request timeout in seconds (default: 60)
        
        # HTTP request headers (default User-Agent and other headers)
        self.HEADERS = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

    def _normalize_url(self, url: str) -> str:
        """
        Normalize URLs to ensure consistent comparison.
        Handles Telegram channels, ssconf:// URLs, and regular URLs.
        
        Args:
            url: The URL to normalize
            
        Returns:
            Normalized version of the URL for comparison
        """
        if url.startswith('ssconf://'):
            url = url.replace('ssconf://', 'https://', 1)
            
        parsed = urlparse(url)
        path = parsed.path.rstrip('/')
        
        if parsed.netloc.startswith('t.me/s/'):
            channel_name = parsed.path.strip('/').lower()
            return f"telegram:{channel_name}"
            
        return f"{parsed.scheme}://{parsed.netloc}{path}"

    def _remove_duplicate_urls(self, channel_configs: List[ChannelConfig]) -> List[ChannelConfig]:
        """
        Remove duplicate URLs from the channel config list.
        Keeps the first occurrence of each URL and removes subsequent duplicates.
        
        Args:
            channel_configs: List of ChannelConfig objects
            
        Returns:
            List of ChannelConfig objects with duplicates removed
        """
        seen_urls = {}
        unique_configs = []
        
        for config in channel_configs:
            normalized_url = self._normalize_url(config.url)
            if normalized_url not in seen_urls:
                seen_urls[normalized_url] = True
                unique_configs.append(config)
                
        return unique_configs

    def is_protocol_enabled(self, protocol: str) -> bool:
        """
        Check if a protocol is enabled in SUPPORTED_PROTOCOLS.
        Also checks protocol aliases.
        """
        if protocol in self.SUPPORTED_PROTOCOLS:
            return True
        for main_protocol, info in self.SUPPORTED_PROTOCOLS.items():
            if 'aliases' in info and protocol in info['aliases']:
                return True
        return False

    def get_enabled_channels(self) -> List[ChannelConfig]:
        """
        Return list of enabled channels only.
        Channels are enabled by default unless their score drops below 25.
        """
        return [channel for channel in self.SOURCE_URLS if channel.enabled]

    def update_channel_stats(self, channel: ChannelConfig, success: bool, response_time: float = 0):
        """
        Update channel statistics after fetch attempt.
        Disables channel if overall score drops below 25.
        
        Parameters:
        - success: True if fetch was successful (default metrics: success_count=0, fail_count=0)
        - response_time: Response time in seconds (default avg_response_time: 0)
        """
        if success:
            channel.metrics.success_count += 1
            channel.metrics.last_success_time = datetime.now()
        else:
            channel.metrics.fail_count += 1
        
        if response_time > 0:
            if channel.metrics.avg_response_time == 0:
                channel.metrics.avg_response_time = response_time
            else:
                channel.metrics.avg_response_time = (channel.metrics.avg_response_time * 0.7) + (response_time * 0.3)
        
        channel.calculate_overall_score()
        
        if channel.metrics.overall_score < 25:
            channel.enabled = False
            
    def adjust_protocol_limits(self, channel: ChannelConfig):
        """
        Dynamically adjust protocol limits based on channel performance.
        Only adjusts if DYNAMIC_PROTOCOL_ADJUSTMENT is enabled (default: True).
        Uses PROTOCOL_BALANCE_FACTOR (default: 1.5) to calculate new limits.
        """
        if not self.DYNAMIC_PROTOCOL_ADJUSTMENT:
            return
            
        for protocol in self.SUPPORTED_PROTOCOLS:
            if protocol in channel.metrics.protocol_counts:
                count = channel.metrics.protocol_counts[protocol]
                if count >= self.SUPPORTED_PROTOCOLS[protocol]["min_configs"]:
                    new_max = min(
                        int(count * self.PROTOCOL_BALANCE_FACTOR),
                        self.MAX_CONFIGS_PER_CHANNEL
                    )
                    if self.SUPPORTED_PROTOCOLS[protocol]["flexible_max"]:
                        self.SUPPORTED_PROTOCOLS[protocol]["max_configs"] = new_max
