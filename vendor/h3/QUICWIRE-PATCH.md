# 本地 h3 补丁

来源：crates.io h3 0.0.8，保留上游 MIT 许可。

仅两项变动：ext.rs 增加 RFC 9484 CONNECT_IP 与私有 QUICWIRE 枚举及解析；shared_state.rs 提供只读 peer_datagram_settings，用于等待 SETTINGS 并验证 RFC 9220/9297 能力。HTTP/3 帧处理及 QPACK 均沿用上游，不自制替代协议。

打包时移除 Cargo 下载缓存标记，并清理上游 README 的两处行尾空格；其余上游源码不变。
