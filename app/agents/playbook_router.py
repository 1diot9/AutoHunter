"""目标打法路由：把资产信号映射到更窄的 worker 挖掘路线。

算法目标：
- 不替代 scorer；scorer 决定资产大致优先级，本模块决定“进去以后先打哪条路”。
- 不生成破坏性 payload；只输出授权测试下的验证重点、证据门槛和快速放弃条件。
- 输出要短，适合注入 worker prompt，避免把通用方法论重复塞满上下文。

资料基线：
- OWASP API Top 10 / WSTG：API 对象级、功能级授权和 IDOR 是 API 路由核心。
- OpenAPI/Swagger：API 文档能直接暴露 paths、parameters、methods，应优先转成授权边界验证。
- Spring Boot Actuator / Nacos / RuoYi / JEECG / TDuck / GraphQL / DevOps / 对象存储：
  这些组件的官方文档暴露了稳定路径和业务语义，适合作为路由信号，而不是让 worker 从零猜。
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from urllib.parse import urlparse


@dataclass(frozen=True)
class RoutePlan:
    route_id: str
    label: str
    confidence: float
    score_bonus: float
    intensity: str
    tags: tuple[str, ...]
    evidence: tuple[str, ...]
    focus: tuple[str, ...]
    avoid: tuple[str, ...]
    finish_hint: str
    alternates: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict:
        return {
            "route_id": self.route_id,
            "label": self.label,
            "confidence": self.confidence,
            "score_bonus": self.score_bonus,
            "intensity": self.intensity,
            "tags": list(self.tags),
            "evidence": list(self.evidence),
            "focus": list(self.focus),
            "avoid": list(self.avoid),
            "finish_hint": self.finish_hint,
            "alternates": list(self.alternates),
        }


@dataclass(frozen=True)
class _RouteDef:
    route_id: str
    label: str
    tag_weights: dict[str, float]
    focus: tuple[str, ...]
    avoid: tuple[str, ...]
    finish_hint: str
    base: float = 0.0
    bonus_cap: float = 4.0
    intensity: str = "normal"
    min_score: float = 1.0


_API_PATH_RE = re.compile(
    r"""(?ix)
    ["'\s(]
    (
      /(?:
        api|rest|service|openapi|graphql|graphiql|v[12]|prod-api|admin-api|dev-api|tduck-api|jeecg-boot|blade|system|
        actuator|nacos|druid|swagger-ui|v2/api-docs|v3/api-docs|doc\.html|knife4j|
        upload|file|import|export|download|register|login|captcha|
        jenkins|gitlab|harbor|grafana|k8s|kubernetes|apisix|kong|minio|s3|oss|\.git|\.env
      )
      [\w./?=&:%@+-]*
    )
    """
)

_ROUTES: tuple[_RouteDef, ...] = (
    _RouteDef(
        "directed_deepen",
        "审核/worker 指令定向深挖",
        {"deepen": 12, "worker_lead": 3, "review_deepen": 3},
        (
            "先执行 deepen_directive 指向的单一路径，不重新做泛侦察",
            "围绕原 finding 的接口/参数补齐 before-after 或越权/敏感数据证据",
            "若该链路被证明不通，finish(no_vuln) 并写清失败点",
        ),
        ("不要把原半成品重复提交", "不要扩散到无关系统"),
        "定向指令验证完仍无实证危害就结束，保留下一步线索。",
        base=2,
        bonus_cap=6,
        intensity="deep",
    ),
    _RouteDef(
        "api_docs_authorization",
        "Swagger/OpenAPI/Knife4j 接口授权边界",
        {"swagger": 5, "openapi": 5, "knife4j": 4, "doc_api": 4, "api_paths_many": 2, "admin_api": 2},
        (
            "优先读取接口文档/paths/parameters，挑 GET 详情、列表、导出、管理 POST/PUT/DELETE",
            "围绕对象级授权(BOLA/IDOR)：替换 path/query/body 中的 id、userId、tenantId、deptId、ids",
            "围绕功能级授权(BFLA)：未登录或低权限访问管理/导出/配置接口",
            "提交前必须证明接口本应受限，且拿到够格数据或真实写操作变化",
        ),
        ("不要只把 swagger/doc.html 暴露当漏洞", "不要遍历全 API；只测高价值端点"),
        "文档只能访问但所有高价值接口 401/403/公开展示时，快速结束。",
        base=1,
        bonus_cap=4,
        intensity="deep",
    ),
    _RouteDef(
        "spring_actuator_exposure",
        "Spring Actuator 暴露面",
        {"actuator": 7, "spring": 2, "env": 2, "heapdump": 3, "prometheus": 1},
        (
            "先确认 /actuator 暴露清单，再只读验证 env/configprops/heapdump/logfile/metrics",
            "目标是提取并验证可用凭证、token、内部服务地址或能导致下一跳的配置",
            "若只有 health/info/metrics 普通状态，不按漏洞提交",
        ),
        ("不要把 health UP 当洞", "不要调用 shutdown 或破坏性管理端点"),
        "只剩 health/info/metrics 且无凭证/敏感配置时结束。",
        base=1,
        bonus_cap=5,
        intensity="deep",
    ),
    _RouteDef(
        "druid_monitor_exposure",
        "Druid 监控台暴露面",
        {"druid": 8},
        (
            "先打开 /druid/index.html 确认是否真实 Druid 控制台，不要因首页是 SPA/门户就放弃",
            "优先只读 sql/wall/datasource/session 等监控接口，提取 SQL/数据源/账号线索",
            "有登录墙则试默认口令 druid/druid 一次；打通则继续拿敏感 SQL/连接串",
        ),
        ("不要把登录页存在当漏洞", "不要破坏监控配置"),
        "404 或仅登录墙且默认口令失败时结束，转打业务 API。",
        base=2,
        bonus_cap=5,
        intensity="deep",
        min_score=2,
    ),
    _RouteDef(
        "graphql_authorization",
        "GraphQL Schema/Resolver 授权边界",
        {"graphql": 8, "graphiql": 4, "graphql_operation": 3, "apollo": 2, "api_paths_many": 1},
        (
            "先只读确认 schema/operation 入口，再按 Query/Mutation 分类挑用户、组织、文件、导出、管理字段",
            "围绕 resolver 做对象级授权：变量里的 id、userId、orgId、tenantId、ids 数组要逐一验证边界",
            "围绕功能级授权：普通用户/未登录是否能访问管理 mutation 或批量导出 query",
            "若 introspection 关闭，也从前端 JS/apollo cache/operationName 提取实际 operation 再验证",
        ),
        ("不要做深度/批量消耗型查询", "不要把 /graphql 存在或 introspection 开启本身当漏洞"),
        "只能访问公开 schema，或所有高价值 resolver 均需鉴权且无对象边界证据时结束。",
        base=1,
        bonus_cap=4,
        intensity="deep",
    ),
    _RouteDef(
        "nacos_config_service",
        "Nacos 配置/服务治理暴露面",
        {"nacos": 8, "config_service": 2, "service_discovery": 1},
        (
            "先判断控制台/API 是否需要鉴权；若开放，优先只读配置、命名空间、服务列表",
            "核心证据是可读到数据库/中间件凭证、JWT/secret、真实业务配置，或可用 token",
            "Nacos 是内部微服务组件，公网暴露本身是强信号，但报告仍要落到可利用配置/凭证",
        ),
        ("不要修改配置、服务权重或下线实例", "不要把登录页存在当漏洞"),
        "不能读配置/服务元数据，或只返回登录页时结束。",
        base=1,
        bonus_cap=5,
        intensity="deep",
    ),
    _RouteDef(
        "devops_control_plane",
        "DevOps/运维控制面暴露面",
        {
            "jenkins": 7, "gitlab": 7, "harbor": 6, "grafana": 5, "kubernetes": 7,
            "apisix": 5, "kong": 5, "nexus": 5, "sonarqube": 4, "devops": 3,
            "anonymous": 2, "token": 2,
        },
        (
            "先判断是否匿名可读或弱鉴权暴露，优先只读项目/仓库/构建/镜像/仪表盘/集群资源",
            "核心证据是可用 token/secret、CI 变量、私有仓库/镜像、K8s secret/config、Grafana 数据源凭证",
            "若有 API token 或 session，验证最小只读受限资源；不要触发构建、部署、删除或修改配置",
        ),
        ("不要触发 job/build/deploy", "不要删除镜像/仓库/Pod/配置", "不要把登录页或版本号单独提交"),
        "只能看到公开登录页/版本页，或匿名只读无敏感资源时结束。",
        base=1,
        bonus_cap=5,
        intensity="deep",
    ),
    _RouteDef(
        "storage_bucket_exposure",
        "对象存储/MinIO/OSS/S3 暴露面",
        {"minio": 6, "storage_console": 4, "s3": 5, "oss": 5, "bucket": 3, "sts": 4, "assume_role": 3, "cloud_storage": 2},
        (
            "先确认 bucket/endpoint/STS/key 是否真实可用，优先只读 list/get 小对象或元数据",
            "重点验证越权读取私有对象、公开列目录、STS 凭证可访问范围、上传回显路径是否可被未授权访问",
            "报告要落到真实对象、敏感文件、可用临时凭证或跨 bucket/租户访问，而不是只发现 endpoint",
        ),
        ("不要覆盖/删除对象", "不要上传大文件或做费用消耗型操作", "不要把公开静态 CDN 当漏洞"),
        "只能访问公开静态资源或 key/STS 无效时结束。",
        base=1,
        bonus_cap=4,
        intensity="normal",
    ),
    _RouteDef(
        "repo_config_secret_exposure",
        "源码/配置/备份泄露可利用链",
        {"git_exposed": 8, "env_file": 7, "source_map": 3, "backup": 4, "secret": 3, "config_file": 3},
        (
            "先只读确认 .git/.env/source map/备份配置是否真实可取，不做大规模拉取",
            "提取 DB/API/JWT/对象存储/第三方 key 后，必须验证最小只读受限资源或登录/API 调用成功",
            "若只有源码片段，优先从路由、接口、签名逻辑转入 SPA/API 授权验证",
        ),
        ("不要把路径存在或无效 key 单独提交", "不要全量下载大型仓库/备份"),
        "配置拿不到可用凭证，或源码只含公开前端逻辑时结束。",
        base=1,
        bonus_cap=5,
        intensity="deep",
    ),
    _RouteDef(
        "ruoyi_lowcode_admin",
        "RuoYi/JEECG/低代码后台 API",
        {
            "ruoyi": 5, "jeecg": 5, "lowcode": 3, "prod_api": 4, "admin_api": 4,
            "system_config": 4, "user_list": 4, "druid": 2, "knife4j": 2,
        },
        (
            "优先验证 /prod-api|/admin-api|/jeecg-boot 下的 config、user、role、dept、dict、export",
            "sys.user.initPassword 这类配置值只是线索，必须继续验证能否登录或调用受限接口",
            "对列表/详情/导出接口做未授权、低权限、tenant/dept/userId/ids 越权验证",
            "对上传/导入接口只做最小可逆验证，证明可控后再看是否能形成实害",
        ),
        ("不要把默认配置值单独提交", "不要只因 doc.html/Knife4j 可见就提交"),
        "配置/用户/导出/上传均不可用或只跳登录时结束。",
        base=1,
        bonus_cap=5,
        intensity="deep",
    ),
    _RouteDef(
        "tduck_form_data",
        "TDuck/表单问卷/数据采集系统",
        {"tduck": 8, "form": 3, "survey": 3, "questionnaire": 3, "data_collection": 2, "register": 1},
        (
            "优先找表单 project/formKey/formId/dataId 的读写边界",
            "验证未授权查看表单数据、导出提交数据、跨表单/跨租户读取或修改",
            "注册/登录只作为入口；真正目标是登录后数据、导出、成员/项目权限",
        ),
        ("不要把可填写公开问卷当漏洞", "不要把注册无验证码单独提交"),
        "只能访问公开表单、无后台数据/导出/越权时结束。",
        base=1,
        bonus_cap=5,
        intensity="deep",
    ),
    _RouteDef(
        "spa_js_api",
        "SPA 前端 JS/API/密钥路线",
        {"spa": 4, "js": 3, "api_paths_many": 3, "secret": 4, "token": 2, "webpack": 2},
        (
            "先用 analyze_javascript 提取接口、路由、鉴权、签名、secret/token 线索",
            "按接口价值排序验证：用户信息、导出、文件、管理、支付/审批、配置",
            "发现 secret/key 后必须证明它能调通受限接口或产生真实影响",
        ),
        ("不要只提交 JS 硬编码", "不要把公开前端接口当未授权"),
        "JS 只有静态资源/公开展示接口，且 secret 无法利用时结束。",
        base=0.5,
        bonus_cap=4,
        intensity="normal",
    ),
    _RouteDef(
        "registration_post_auth",
        "注册/验证码/登录后下游危害",
        {"register": 5, "captcha": 2, "sms": 3, "login": 1, "form": 1, "admin_api": 1},
        (
            "注册无验证码只是入口；注册后立刻测用户信息、表单、导出、上传、管理 API",
            "验证码只区分短信 OTP 与图形验证码；图形答案回显通常不作为成果",
            "若能创建账号，重点找水平越权、批量导出、角色/租户参数和敏感写操作",
        ),
        ("不要把注册成功本身提交", "不要把图形验证码答案回显当洞"),
        "注册后无任何受限资源/越权/导出/写操作时结束。",
        base=0.5,
        bonus_cap=3,
        intensity="normal",
    ),
    _RouteDef(
        "upload_import_export",
        "上传/导入/导出/文件访问路线",
        {"upload": 5, "import": 4, "export": 4, "download": 3, "file": 2},
        (
            "先找真实对象 ID 或业务上下文，再测文件读写权限边界",
            "上传先做安全文本/图片最小验证，再判断扩展名、MIME、路径回显、访问控制",
            "导出/下载重点测 ids、fileId、path、tenantId、deptId 是否越权",
        ),
        ("不要只因能上传 txt 就提交", "不要做破坏性覆盖/删除"),
        "无法证明可执行、敏感数据读取或越权文件访问时结束。",
        base=0.5,
        bonus_cap=4,
        intensity="normal",
    ),
    _RouteDef(
        "business_state_idor",
        "业务状态机/IDOR/批量接口",
        {"business": 4, "payment": 3, "approval": 3, "order": 3, "api_paths_many": 2, "login": 1},
        (
            "先找列表/详情/提交/审批/撤回/支付状态等对象 ID",
            "做最小 before-after：对象存在、变更请求、状态确实变化或越权读到他人资源",
            "重点参数：id、ids、userId、studentId、deptId、tenantId、status、role、amount",
        ),
        ("不要用不存在的 ID 证明写操作", "不要只看 success=true，必须证明状态变化"),
        "找不到真实对象 ID 或无法安全证明状态变化时结束。",
        base=0.5,
        bonus_cap=4,
        intensity="deep",
    ),
    _RouteDef(
        "auth_gateway_post_login",
        "SSO/CAS/统一认证后置深挖",
        {"auth_gateway": 5, "sso": 5, "cas": 5, "leaked_creds": 3},
        (
            "统一认证本身通常难出；若有泄露凭证，登录只作为进入具体业务系统的第 0 步",
            "优先从跳转应用、ticket/service、个人中心链接找到具体业务系统，再测受限资源",
            "必须实证登录后读到够格数据、越权操作或进入具体业务系统后的独立漏洞",
        ),
        ("不要把登录成功/CASTGC/session 本身提交", "不要空泛写可能访问其它系统"),
        "只有认证中心/个人中心且无具体业务实害时结束或交 deepen_lead。",
        base=-0.5,
        bonus_cap=2,
        intensity="quick",
    ),
    _RouteDef(
        "generic_admin_api",
        "通用后台/API 快速验证",
        {"admin": 3, "login": 2, "api_paths_few": 1, "nonstandard_port": 1},
        (
            "优先登录/API/上传/导出/配置/用户列表，不做泛目录",
            "若 3-5 个动作内找不到可交互点或高价值接口，快速收敛",
            "有 API 后转入 IDOR/BFLA/文件/业务状态机验证",
        ),
        ("不要泛扫空转", "不要提交后台登录页存在"),
        "无登录、无 API、无表单、无上传下载时结束。",
        base=0,
        bonus_cap=2,
        intensity="normal",
        min_score=0.5,
    ),
    _RouteDef(
        "static_low_value",
        "低价值静态/门户快速收敛",
        {"static": 5, "portal": 4, "news": 4, "marketing": 3, "public_display": 2},
        (
            "只确认是否存在登录/API/表单/上传/JS 接口；没有就立刻结束",
            "若发现 JS API 或后台入口，切换到 SPA/API/后台路线",
        ),
        ("不要在新闻/官网/静态页上路径穷举", "不要把公开内容当泄露"),
        "无交互点时 3-5 个动作内 finish(no_vuln)。",
        base=-1,
        bonus_cap=-2,
        intensity="quick",
        min_score=2,
    ),
)


def _norm(text: str) -> str:
    return (text or "").lower()


def _path(url: str) -> str:
    try:
        return urlparse(url or "").path or ""
    except Exception:
        return ""


def _port(url: str) -> int:
    from app.urlnorm import safe_port, safe_urlparse
    try:
        p = safe_urlparse(url or "")
        port = safe_port(p)
        if port:
            return port
        return 443 if p.scheme == "https" else 80
    except Exception:
        return 80


def _add_signal(signals: dict[str, list[str]], tag: str, evidence: str) -> None:
    if not evidence:
        evidence = tag
    bucket = signals.setdefault(tag, [])
    if evidence not in bucket and len(bucket) < 4:
        bucket.append(evidence[:160])


def _extract_paths(text: str) -> list[str]:
    paths: list[str] = []
    for m in _API_PATH_RE.finditer(f" {text or ''} "):
        path = m.group(1).strip().rstrip(".,;)")
        if path and path not in paths:
            paths.append(path[:180])
        if len(paths) >= 30:
            break
    return paths


def extract_route_signals(
    *,
    url: str,
    title: str = "",
    server: str = "",
    body: str = "",
    priority_reason: str = "",
    src_type: str = "edusrc",
    source: str = "",
    deepen_context: dict | None = None,
    leaked_creds: list[dict] | None = None,
) -> dict[str, list[str]]:
    """抽取稳定路由信号，返回 tag -> evidence[]。"""
    signals: dict[str, list[str]] = {}
    path = _path(url)
    port = _port(url)
    combined = "\n".join([url, title, server, body[:12000], priority_reason, source])
    low = _norm(combined)

    if deepen_context:
        _add_signal(signals, "deepen", str(deepen_context.get("directive") or deepen_context)[:160])
        src = str(deepen_context.get("source") or "")
        if src == "worker_lead":
            _add_signal(signals, "worker_lead", src)
        if "review" in src or "ai" in src:
            _add_signal(signals, "review_deepen", src)
    if source == "killsweep":
        _add_signal(signals, "deepen", "通杀验证目标")
    if leaked_creds:
        _add_signal(signals, "leaked_creds", f"leaked_creds×{len(leaked_creds)}")

    checks = [
        ("swagger", ("swagger-ui", "/swagger", "swagger ui")),
        ("openapi", ("openapi", "/v3/api-docs", "/v2/api-docs")),
        ("graphql", ("/graphql",)),
        ("graphql_operation", ("operationname", "__schema", "__typename", "query {", "mutation {")),
        ("graphiql", ("graphiql", "graphql playground", "apollo studio")),
        ("apollo", ("apollo", "__typename", "apollo-client")),
        ("knife4j", ("knife4j", "doc.html", "/webjars")),
        ("doc_api", ("api-docs", "接口文档", "在线接口")),
        ("actuator", ("/actuator", "spring boot actuator")),
        ("spring", ("spring", "springboot", "spring boot")),
        ("env", ("/actuator/env", "propertysources", "systemproperties")),
        ("heapdump", ("heapdump", "/actuator/heapdump")),
        ("prometheus", ("prometheus", "/actuator/prometheus")),
        ("nacos", ("nacos", "/nacos", "console-ui")),
        ("config_service", ("configuration management", "配置中心", "configurations", "/v1/cs/configs")),
        ("service_discovery", ("service list", "服务列表", "/v1/ns/instance")),
        ("ruoyi", ("ruoyi", "若依", "ry-ui", "sys.user.initpassword")),
        ("jeecg", ("jeecg", "jeecg-boot", "积木报表", "jimureport")),
        ("lowcode", ("低代码", "online form", "online表单", "表单设计器")),
        ("prod_api", ("/prod-api",)),
        ("admin_api", ("/admin-api", "/admin/")),
        ("system_config", ("configkey", "sys.user.initpassword", "/system/config")),
        ("user_list", ("/system/user/list", "username", "userName")),
        ("druid", ("druid stat", "/druid", "druid-version")),
        ("jenkins", ("jenkins", "/jenkins", "x-jenkins")),
        ("gitlab", ("gitlab", "gitlab-ci", "/users/sign_in")),
        ("harbor", ("harbor", "harbor registry", "/harbor")),
        ("grafana", ("grafana", "grafana_session", "/grafana")),
        ("kubernetes", ("kubernetes dashboard", "k8s", "kubeconfig", "/api/v1/namespaces")),
        ("apisix", ("apisix", "apache apisix", "/apisix/admin")),
        ("kong", ("kong", "kong admin")),
        ("nexus", ("nexus repository", "sonatype nexus")),
        ("sonarqube", ("sonarqube", "sonar")),
        ("devops", ("devops", "ci/cd", "持续集成", "镜像仓库", "制品库")),
        ("anonymous", ("anonymous", "匿名", "未登录访问")),
        ("tduck", ("tduck", "填鸭", "/tduck-api")),
        ("form", ("表单", "form", "survey", "问卷")),
        ("survey", ("survey", "问卷")),
        ("questionnaire", ("questionnaire", "问卷调查")),
        ("data_collection", ("数据采集", "data collection", "提交数据")),
        ("spa", ("vue", "react", "angular", "__webpack", "webpack", "single-spa")),
        ("js", (".js", "<script", "javascript")),
        ("secret", ("secret", "appsecret", "accesskey", "privatekey", "clientsecret")),
        ("token", ("token", "jwt", "authorization")),
        ("minio", ("x-minio", "minio console", "/minio/")),
        ("storage_console", ("minio console", "bucket browser", "object browser")),
        ("s3", ("s3", "amazons3", "x-amz-", "bucket")),
        ("oss", ("oss", "aliyun", "x-oss-", "bucket")),
        ("bucket", ("bucket", "对象存储")),
        ("sts", ("sts", "securitytoken", "assume-role")),
        ("assume_role", ("assumerole", "assume-role", "assume role")),
        ("cloud_storage", ("云存储", "对象存储", "x-oss-", "x-amz-")),
        ("git_exposed", ("/.git/config", "[core]", "repositoryformatversion")),
        ("env_file", ("/.env", "app_key", "db_password", "db_database", "spring.datasource.password")),
        ("source_map", (".js.map", "sourcemap", "sourceMappingURL")),
        ("backup", (".bak", ".zip", ".tar.gz", "backup", "备份")),
        ("config_file", ("application.yml", "application.properties", "config.json", "settings.py")),
        ("register", ("register", "注册", "/register")),
        ("captcha", ("captcha", "验证码")),
        ("sms", ("sms", "短信", "otp")),
        ("login", ("login", "登录", "signin", "password")),
        ("upload", ("upload", "上传")),
        ("import", ("import", "导入")),
        ("export", ("export", "导出")),
        ("download", ("download", "下载")),
        ("file", ("file", "附件", "文件")),
        ("business", ("审批", "报名", "预约", "成绩", "工单", "流程", "业务")),
        ("payment", ("支付", "缴费", "订单", "退款", "发票")),
        ("approval", ("审批", "审核", "流程")),
        ("order", ("订单", "预约", "报名")),
        ("auth_gateway", ("统一身份认证", "统一认证", "认证平台", "登录中心", "authserver")),
        ("sso", ("sso", "single sign-on", "单点登录")),
        ("cas", ("cas", "castgc")),
        ("static", ("static", "assets", "cdn", "纯前端", "静态")),
        ("portal", ("官网", "门户", "首页", "学校首页", "学院首页")),
        ("news", ("新闻网", "新闻", "公告")),
        ("marketing", ("宣传", "简介", "概况", "联系我们")),
        ("public_display", ("展示", "可视化大屏", "数据大屏")),
    ]
    for tag, needles in checks:
        for needle in needles:
            if needle.lower() in low:
                _add_signal(signals, tag, needle)
                break

    paths = _extract_paths(combined)
    if len(paths) >= 3:
        _add_signal(signals, "api_paths_many", f"api_paths×{len(paths)}")
    elif paths:
        _add_signal(signals, "api_paths_few", paths[0])
    for p in paths[:12]:
        plow = p.lower()
        if "swagger" in plow or "api-docs" in plow or "doc.html" in plow:
            _add_signal(signals, "doc_api", p)
        if "actuator" in plow:
            _add_signal(signals, "actuator", p)
        if "graphql" in plow:
            _add_signal(signals, "graphql", p)
        if "nacos" in plow:
            _add_signal(signals, "nacos", p)
        if "prod-api" in plow:
            _add_signal(signals, "prod_api", p)
        if "admin-api" in plow:
            _add_signal(signals, "admin_api", p)
        if "tduck-api" in plow:
            _add_signal(signals, "tduck", p)
        if "upload" in plow:
            _add_signal(signals, "upload", p)
        if "export" in plow:
            _add_signal(signals, "export", p)
        if "import" in plow:
            _add_signal(signals, "import", p)
        if "register" in plow:
            _add_signal(signals, "register", p)
        if ".git" in plow:
            _add_signal(signals, "git_exposed", p)
        if ".env" in plow:
            _add_signal(signals, "env_file", p)
        if "minio" in plow:
            _add_signal(signals, "minio", p)
        if "/s3" in plow or "/oss" in plow:
            _add_signal(signals, "cloud_storage", p)
        if any(x in plow for x in ("jenkins", "gitlab", "harbor", "grafana", "apisix", "kong", "nexus", "sonar")):
            _add_signal(signals, "devops", p)

    if port not in (80, 443):
        _add_signal(signals, "nonstandard_port", f":{port}")
    if path and any(x in path.lower() for x in ("admin", "console", "manager")):
        _add_signal(signals, "admin", path)
    if "enterprise" in (src_type or "").lower():
        _add_signal(signals, "enterprise", "src_type=enterprise")
    return signals


def route_target(
    *,
    url: str,
    title: str = "",
    server: str = "",
    body: str = "",
    priority_reason: str = "",
    src_type: str = "edusrc",
    source: str = "",
    deepen_context: dict | None = None,
    leaked_creds: list[dict] | None = None,
) -> RoutePlan:
    signals = extract_route_signals(
        url=url,
        title=title,
        server=server,
        body=body,
        priority_reason=priority_reason,
        src_type=src_type,
        source=source,
        deepen_context=deepen_context,
        leaked_creds=leaked_creds,
    )
    scored: list[tuple[float, _RouteDef, list[str], list[str]]] = []
    for route in _ROUTES:
        score = route.base
        tags: list[str] = []
        evidence: list[str] = []
        for tag, weight in route.tag_weights.items():
            if tag in signals:
                score += weight
                tags.append(tag)
                evidence.extend(signals[tag][:2])
        if not tags:
            continue
        if score >= route.min_score:
            scored.append((score, route, tags, evidence))

    if not scored:
        fallback = next(r for r in _ROUTES if r.route_id == "generic_admin_api")
        return _build_plan(0.0, fallback, [], ["普通资产"], [])

    scored.sort(key=lambda x: x[0], reverse=True)
    block_static = re.search(
        r"/druid|/actuator|/nacos|暴露端点|killchain:",
        "\n".join([url or "", title or "", priority_reason or "", body[:4000]]),
        re.I,
    )
    if block_static:
        filtered = [x for x in scored if x[1].route_id != "static_low_value"]
        if filtered:
            scored = filtered
        else:
            fallback = next(r for r in _ROUTES if r.route_id == "generic_admin_api")
            return _build_plan(2.0, fallback, ["druid"], ["暴露高价值端点，禁止静态收敛"], [])
    if scored[0][1].route_id == "static_low_value" and len(scored) > 1 and scored[1][0] >= scored[0][0] - 1:
        scored = [scored[1], scored[0], *scored[2:]]
    top_score, route, tags, evidence = scored[0]
    alternates = [r.label for _, r, _, _ in scored[1:4] if r.route_id != route.route_id]
    return _build_plan(top_score, route, tags, evidence, alternates)


def _build_plan(score: float, route: _RouteDef, tags: list[str], evidence: list[str], alternates: list[str]) -> RoutePlan:
    confidence = min(0.98, max(0.35, score / 12.0))
    if route.bonus_cap < 0:
        score_bonus = route.bonus_cap
    else:
        score_bonus = min(route.bonus_cap, max(0.0, score / 3.0))
    clean_evidence: list[str] = []
    for item in evidence:
        s = str(item or "").strip()
        if s and s not in clean_evidence:
            clean_evidence.append(s)
    return RoutePlan(
        route_id=route.route_id,
        label=route.label,
        confidence=round(confidence, 2),
        score_bonus=round(score_bonus, 1),
        intensity=route.intensity,
        tags=tuple(dict.fromkeys(tags)),
        evidence=tuple(clean_evidence[:8]),
        focus=route.focus,
        avoid=route.avoid,
        finish_hint=route.finish_hint,
        alternates=tuple(alternates),
    )


def render_playbook_block(plan: RoutePlan) -> str:
    """渲染给 worker 的短上下文块。"""
    lines = [
        "# 打法路由（系统根据目标指纹自动生成，优先执行）",
        f"- 路线：{plan.label}（confidence={plan.confidence:.2f}, intensity={plan.intensity}）",
    ]
    if plan.tags:
        lines.append(f"- 命中信号：{', '.join(plan.tags[:8])}")
    if plan.evidence:
        lines.append("- 证据片段：" + "；".join(plan.evidence[:5]))
    lines.append("- 先做：")
    for item in plan.focus[:4]:
        lines.append(f"  - {item}")
    if plan.avoid:
        lines.append("- 避免：")
        for item in plan.avoid[:3]:
            lines.append(f"  - {item}")
    lines.append(f"- 快速收敛：{plan.finish_hint}")
    if plan.alternates:
        lines.append(f"- 若首选路线无攻击面，再切：{' / '.join(plan.alternates[:3])}")
    return "\n".join(lines) + "\n\n"


def append_route_reason(reason: str, plan: RoutePlan) -> str:
    """把路由结果压缩进 priority_reason，供排序和看板解释。"""
    base = reason or "普通资产"
    tag = f"route:{plan.route_id}/{plan.label}/+{plan.score_bonus:g}"
    if tag in base:
        return base
    if len(base) > 420:
        base = base[:420].rstrip() + "..."
    return f"{base} · {tag}"
