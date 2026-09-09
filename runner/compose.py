"""Validate Docker's normalized Compose JSON before any container is started."""

from .protocol import IMAGE

SERVICE_KEYS = {
    "image", "profiles", "init", "mem_limit", "cpus", "pids_limit", "cap_drop",
    "cap_add", "security_opt", "networks", "volumes", "environment", "command",
    "entrypoint", "working_dir", "user", "read_only", "tmpfs", "healthcheck",
    "depends_on", "restart", "platform", "labels", "hostname", "stop_grace_period",
    "ports", "privileged", "network_mode", "devices", "expose", "pull_policy",
}


def validate_compose(config, images, exceptions=(), allow_exceptions=False):
    services = config.get("services", {})
    if not services or not {"vulnerable", "patched"}.issubset(services):
        raise ValueError("Compose requires vulnerable and patched services")
    allowed = {}
    for entry in exceptions:
        if not isinstance(entry, dict) or not entry.get("reason") or not entry.get("rule"):
            raise ValueError("Isolation exception needs rule and reason")
        allowed[entry["rule"]] = entry["reason"]

    def require(condition, rule):
        if not condition and not (allow_exceptions and rule in allowed):
            raise ValueError(f"Compose isolation rule: {rule}")

    unknown = set(config) - {"name", "services", "networks", "volumes"}
    if unknown:
        raise ValueError(f"Unsupported Compose sections: {sorted(unknown)}")
    for name, network in config.get("networks", {}).items():
        require(network.get("internal") is True, f"network.{name}.internal")
        if (set(network) - {"name", "internal", "labels", "driver", "ipam"}
                or network.get("ipam") or network.get("driver", "bridge") != "bridge"):
            raise ValueError(f"Unsupported network configuration: {name}")
    for name, volume in config.get("volumes", {}).items():
        if volume and set(volume) - {"name", "labels"}:
            raise ValueError(f"External/driver volumes are forbidden: {name}")
    project = config["name"]
    for category in ("networks", "volumes"):
        for name, value in config.get(category, {}).items():
            if value and value.get("name", f"{project}_{name}") != f"{project}_{name}":
                raise ValueError(f"Resource name must be project-scoped: {category}.{name}")
    for name, service in services.items():
        unknown = set(service) - SERVICE_KEYS
        if unknown:
            raise ValueError(f"Unsupported Compose keys for {name}: {sorted(unknown)}")
        if name in images:
            if service.get("image") != images[name] or service.get("profiles") != [name]:
                raise ValueError(f"Wrong image or profile for {name}")
        elif not IMAGE.fullmatch(service.get("image", "")):
            raise ValueError(f"Auxiliary service must pin image digest: {name}")
        dependencies = service.get("depends_on", {})
        if any(dependency in images and dependency != name for dependency in dependencies):
            raise ValueError("Dependencies cannot activate a target variant")
        if name in images and any(
                mount.get("target") == "/lab/results" and mount.get("read_only")
                for mount in service.get("volumes", [])):
            raise ValueError("Result volume must be writable")
        require(not service.get("ports"), f"service.{name}.ports")
        require(not service.get("privileged"), f"service.{name}.privileged")
        require(not service.get("devices"), f"service.{name}.devices")
        require(not service.get("network_mode"), f"service.{name}.network_mode")
        require(not service.get("cap_add"), f"service.{name}.cap_add")
        require("ALL" in service.get("cap_drop", []), f"service.{name}.cap_drop")
        require(any(s in {"no-new-privileges:true", "no-new-privileges"}
                    for s in service.get("security_opt", [])), f"service.{name}.no_new_privileges")
        if any(s not in {"no-new-privileges:true", "no-new-privileges"} for s in service.get("security_opt", [])):
            raise ValueError("Additional security_opt settings are unsupported")
        if any(float(service.get(k, 0)) <= 0 for k in ("mem_limit", "cpus", "pids_limit")):
            raise ValueError(f"Positive resource limits required: {name}")
        if service.get("restart", "no") != "no":
            raise ValueError("Automatic service restarts are forbidden")
        require(bool(service.get("networks")), f"service.{name}.networks")
        for network in service.get("networks", {}):
            if network not in config.get("networks", {}):
                raise ValueError("Undeclared network")
        for mount in service.get("volumes", []):
            if mount.get("type") != "volume":
                require(False, f"service.{name}.bind_mounts")
                continue
            if mount.get("source") not in config.get("volumes", {}):
                raise ValueError("Anonymous or external volumes are forbidden")
        if name not in images:
            health = service.get("healthcheck", {})
            if health.get("disable") or not health.get("test") or health["test"][0] == "NONE":
                raise ValueError(f"Auxiliary service needs healthcheck: {name}")
    return config
