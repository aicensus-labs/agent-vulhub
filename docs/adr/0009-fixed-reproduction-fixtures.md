# Version and Hash All Reproduction Fixtures

攻击输入、正常输入、模拟数据和固定模型输出必须纳入每个环境的 `fixtures/` 并记录内容哈希；随机种子和相关环境变量显式固定，运行时不得抓取未锁定的攻击材料。需要外部服务时使用容器内的确定性模拟服务，以保证重复运行测试的是同一输入。

**Status**: accepted
