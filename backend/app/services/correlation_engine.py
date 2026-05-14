from collections import defaultdict

from loguru import logger

from app.models.threat_intel import IOCIndicator, IOCType


class CorrelationEngine:
    """Correlate and connect related IOCs across threat intelligence data."""

    @staticmethod
    def correlate_indicators(indicators: list[IOCIndicator]) -> dict[str, list[IOCIndicator]]:
        """
        Group related indicators together.

        Returns: dict of IOC value -> list of correlated indicators
        """
        if not indicators:
            return {}

        correlations: dict[str, list[IOCIndicator]] = defaultdict(list)

        for indicator in indicators:
            primary_key = f"{indicator.ioc_type}:{indicator.value}"
            correlations[primary_key].append(indicator)

            if indicator.associated_domains:
                for domain in indicator.associated_domains:
                    key = f"{IOCType.DOMAIN}:{domain}"
                    correlations[key].extend(
                        [i for i in indicators if i.ioc_type == IOCType.DOMAIN and i.value == domain]
                    )

            if indicator.associated_ips:
                for ip in indicator.associated_ips:
                    key = f"{IOCType.IP}:{ip}"
                    correlations[key].extend(
                        [i for i in indicators if i.ioc_type == IOCType.IP and i.value == ip]
                    )

        return dict(correlations)

    @staticmethod
    def find_common_infrastructure(indicators: list[IOCIndicator]) -> dict[str, list[str]]:
        """
        Identify common infrastructure across indicators.

        Returns: dict of infrastructure -> list of IOCs using it
        """
        infrastructure: dict[str, list[str]] = defaultdict(list)

        for indicator in indicators:
            if indicator.associated_ips:
                for ip in indicator.associated_ips:
                    infrastructure[f"ip:{ip}"].append(f"{indicator.ioc_type}:{indicator.value}")

            if indicator.associated_domains:
                for domain in indicator.associated_domains:
                    infrastructure[f"domain:{domain}"].append(f"{indicator.ioc_type}:{indicator.value}")

            if indicator.malware_families:
                for family in indicator.malware_families:
                    infrastructure[f"malware:{family}"].append(f"{indicator.ioc_type}:{indicator.value}")

        return dict(infrastructure)

    @staticmethod
    def calculate_correlation_score(
        indicator1: IOCIndicator, indicator2: IOCIndicator
    ) -> float:
        """Calculate how strongly two indicators are correlated (0.0 to 1.0)."""
        score = 0.0

        if indicator1.ioc_type == indicator2.ioc_type and indicator1.value == indicator2.value:
            return 1.0

        if indicator2.value in indicator1.associated_domains:
            score += 0.8
        if indicator2.value in indicator1.associated_ips:
            score += 0.8

        shared_malware = set(indicator1.malware_families) & set(indicator2.malware_families)
        if shared_malware:
            score += min(0.6, len(shared_malware) * 0.3)

        shared_sources = set(indicator1.sources) & set(indicator2.sources)
        if shared_sources:
            score += min(0.5, len(shared_sources) * 0.25)

        shared_tags = set(indicator1.tags) & set(indicator2.tags)
        if shared_tags:
            score += min(0.3, len(shared_tags) * 0.15)

        return min(1.0, score)

    @staticmethod
    def build_threat_graph(indicators: list[IOCIndicator]) -> dict:
        """Build a threat graph showing relationships between IOCs."""
        graph = {
            "nodes": [],
            "edges": [],
        }

        seen_nodes = set()
        for indicator in indicators:
            node_id = f"{indicator.ioc_type}:{indicator.value}"
            if node_id not in seen_nodes:
                graph["nodes"].append({
                    "id": node_id,
                    "label": indicator.value,
                    "type": indicator.ioc_type.value,
                    "threat_level": indicator.threat_level.value,
                    "risk_score": indicator.risk_score,
                })
                seen_nodes.add(node_id)

        for i, indicator1 in enumerate(indicators):
            for indicator2 in indicators[i + 1:]:
                score = CorrelationEngine.calculate_correlation_score(indicator1, indicator2)
                if score > 0.3:
                    node1 = f"{indicator1.ioc_type}:{indicator1.value}"
                    node2 = f"{indicator2.ioc_type}:{indicator2.value}"
                    graph["edges"].append({
                        "source": node1,
                        "target": node2,
                        "weight": score,
                    })

        logger.info(
            "threat graph built: nodes={}, edges={}",
            len(graph["nodes"]),
            len(graph["edges"]),
        )

        return graph

    @staticmethod
    def identify_campaigns(indicators: list[IOCIndicator]) -> dict[str, list[IOCIndicator]]:
        """Group indicators into potential threat campaigns based on commonalities."""
        campaigns: dict[str, list[IOCIndicator]] = defaultdict(list)

        for indicator in indicators:
            campaign_keys = []

            if indicator.malware_families:
                for family in indicator.malware_families:
                    campaign_keys.append(f"malware:{family}")

            if indicator.associated_ips and len(indicator.associated_ips) <= 3:
                for ip in indicator.associated_ips:
                    campaign_keys.append(f"infrastructure:{ip}")

            if not campaign_keys:
                campaign_keys.append(f"{indicator.ioc_type}:{indicator.threat_level.value}")

            for key in campaign_keys:
                campaigns[key].append(indicator)

        return dict(campaigns)

    @staticmethod
    def get_investigation_recommendations(indicators: list[IOCIndicator]) -> list[str]:
        """Generate investigation recommendations based on IOC correlations."""
        recommendations = []

        high_risk_count = sum(1 for i in indicators if i.risk_score >= 80.0)
        if high_risk_count >= 3:
            recommendations.append("Multiple high-risk indicators detected. Escalate to incident response team.")

        malware_families = set()
        for indicator in indicators:
            malware_families.update(indicator.malware_families)

        if "ransomware" in [f.lower() for f in malware_families]:
            recommendations.append("Ransomware detected. Isolate affected systems immediately.")

        if "botnet" in [f.lower() for f in malware_families]:
            recommendations.append("Botnet infrastructure identified. Monitor command-and-control communications.")

        domains = set()
        for indicator in indicators:
            if indicator.ioc_type == IOCType.DOMAIN:
                domains.add(indicator.value)
            domains.update(indicator.associated_domains)

        if len(domains) >= 5:
            recommendations.append("Multiple related domains detected. Investigate for domain generation algorithm (DGA).")

        ips = set()
        for indicator in indicators:
            if indicator.ioc_type == IOCType.IP:
                ips.add(indicator.value)
            ips.update(indicator.associated_ips)

        if len(ips) >= 5:
            recommendations.append(
                "Multiple IP addresses correlated. Check for fast-flux network or distributed infrastructure."
            )

        if not recommendations:
            recommendations.append("Continue normal threat hunting and monitoring procedures.")

        return recommendations
