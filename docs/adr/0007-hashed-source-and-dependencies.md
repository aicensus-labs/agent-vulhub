# Pin Source and Dependencies by Content Hash

构建可以联网获取源码和依赖，但每一项输入必须由 URL、完整 commit 或版本锁以及内容哈希固定；基础镜像使用 digest。环境支持缓存和离线构建，Git 仓库不强制携带所有上游源码与依赖，以平衡可重建性、仓库体积和第三方许可。

**Status**: accepted
