# Runbook

## Task 1

```bash
./bin/run_task1.sh <target>
```

说明：

- 生成目标画像、侦察事实、漏洞候选、验证计划和报告骨架
- 自动接入本地可用的 `searchsploit`
- 若 `nmap` 不在 `PATH`，流程不会中断
- 若已有授权扫描结果，可用 `RECON_INPUT_DIR=/path/to/recon_dir ./bin/run_task1.sh <target>` 导入
- 导入目录支持放置 `nmap.txt` 或 `*nmap*.txt`，脚本会自动识别 SSH/SFTP 候选端口并继续漏洞匹配

批量导入多台主机：

```bash
./bin/run_task1_batch.sh <recon_dir>
```

说明：

- 适用于一个 `nmap.txt` 中包含多台主机扫描结果的场景
- 会按主机拆分结果，并分别生成 `runs/<RUN_PREFIX>_<target>/`
- 可用 `TARGETS=ip1,ip2` 只选择部分主机
- 汇总文件输出到 `runs/<RUN_PREFIX>__batch/task1_batch_runs.json`

## Task 2

```bash
./bin/run_task2.sh [log_dir]
```

说明：

- 默认使用 `task2/TOOLS/samples/`
- 真实跑数时，建议每个数据集单独放一个目录，再把该目录作为参数传入
- 若目录内有 `baseline/` 和 `current/`，将自动启用历史基线模式
- 不要把无关样例、策略文件和不同来源日志混放在同一目录
- 输出基线、异常分、告警和文档
- 详细使用方式见 [task2_intranet_manual.md](task2_intranet_manual.md)

## Task 3

```bash
./bin/run_task3.sh [nginx_t_file_or_target]
```

说明：

- 若参数是本地文件，则把它当成 `nginx -T` 输出解析
- 若参数是本地目录，则递归导入原始 nginx `conf/` 目录并按 `include` 关系解析（适用于 `nginx -T` 失败场景）
- 若本地存在 `nginx` 命令，也会尝试采集 `nginx -T` 和 `nginx -V`
