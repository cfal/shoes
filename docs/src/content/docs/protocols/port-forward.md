---
title: "Port Forward"
description: shoes port forward configuration.
---

The field sketches below contain placeholders, not runnable values. Use a complete example when configuring a deployment.

## Server

```yaml
protocol:
  type: portforward            # Alias: forward
  targets: string | [string]   # Target address(es)
```


## Client

```yaml
protocol:
  type: portforward            # Aliases: noop
```

Passes through the raw connection without protocol wrapping. Useful for testing or transparent proxying.
