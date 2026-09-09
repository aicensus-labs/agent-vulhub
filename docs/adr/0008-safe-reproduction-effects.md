# Use Safe, Container-Bounded Reproduction Effects

PoC 只能在隔离容器内产生可验证、可逆的 canary 效果，不能读取真实凭据、访问宿主机资源或向外部目标发送数据。破坏性 CVE 必须用隔离 fixture 和受控替代效果证明能力边界，并记录替代效果与真实影响的关系，以避免用危险载荷换取复现证据。

**Status**: accepted
