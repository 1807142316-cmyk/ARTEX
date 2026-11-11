---
name: container-inspect-review
description: 审查已保存 Docker container inspect JSON；需要检查容器权限、用户、命名空间、挂载和隔离配置而不读取容器环境秘密时使用。
category: 容器配置审计
license: AGPL-3.0-only
compatibility: Python 3.10+ standard library; offline Docker inspect JSON; Linux and Windows
---

# 容器隔离配置复核

输入是已经保存的 Docker 容器 inspect JSON 数组，1–1000 个对象、上限 8 MiB。每个对象含 Config、HostConfig、Mounts；挂载项保留 Source、Destination、RW。镜像 inspect 不包含所需运行字段，不能替代。采集记录需包含运行时版本和容器对应资产引用。

运行 `python3 "${SKILL_DIR}/scripts/run.py" /path/to/inspect.json`。退出 0 输出 JSON；退出 2 的标准错误 JSON 指出字段或结构错误。输出按 container_index 对应原输入，不输出名称、环境变量、命令或挂载源路径，保留 `input_sha256`。

复核 privileged、root/未指定用户、可写根文件系统、host 网络/PID、宽泛新增能力、unconfined seccomp、未设置 no-new-privileges、引擎 socket 挂载与可写挂载数量。已检查字段缺失保持 unknown；CapAdd/SecurityOpt 的 null 按 Docker inspect 的空配置处理。具名非 root 用户也不能证明最终 UID、映射或 rootless 模式。

结果是配置风险线索，需要结合运行时、宿主策略、AppArmor/SELinux、user namespace、业务要求和文件权限复核；镜像 User 或单一标志不能证明安全。引擎 socket 检查只覆盖记录中的常见路径，自定义或转发 socket 需要人工核查。脚本不连接 Docker daemon、不执行容器、不读取文件内容、不修改配置。

依据：<https://docs.docker.com/reference/cli/docker/inspect/>、<https://docs.docker.com/engine/security/>。本工作流与脚本由 ARTEX 编写，仅依赖 Python 标准库。
