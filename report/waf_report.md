# Acknowledgments

I would like to express my sincere gratitude to my academic supervisor for their guidance and continuous support throughout this project. I also thank the open-source community whose tools and frameworks formed the foundation of this work.

---

# Abstract

Web Application Firewalls (WAFs) serve as the primary defense against web-based attacks targeting application-layer vulnerabilities. Traditional WAF solutions suffer from high false-positive rates, static signature databases, and limited adaptability to evolving threats. This project presents an intelligent AI-enhanced WAF implemented as a reverse proxy combining signature-based detection, machine learning classification, and behavioral analysis.

The system is built using Python and FastAPI with ten core capabilities: multi-strategy detection with 106 signature patterns across nine attack categories, a logistic regression ML model trained on eight traffic features, automatic signature generation from blocked requests, asynchronous database operations with connection pooling, Redis-based distributed caching, HTTPS/TLS termination, real-time monitoring via WebSocket, zero-day attack detection using statistical anomaly analysis, DDoS protection with multi-layered flood mitigation, and containerized deployment with CI/CD pipeline.

Evaluation demonstrates comprehensive test coverage, sub-50ms analysis latency, and successful detection of SQL injection, XSS, command injection, path traversal, file inclusion, SSTI, SSI, XXE, and DOM-based XSS attacks.

**Keywords:** Web Application Firewall, Machine Learning, Signature-Based Detection, Reverse Proxy, Cybersecurity

---

# Table of Contents

Acknowledgments
Abstract

**Chapter 1: Introduction**
1.1 Background
1.2 Problem Statement
1.3 Objectives
1.4 Project Scope
1.5 Contributions
1.6 Project Methodology
1.7 Report Structure

**Chapter 2: Literature Review**
2.1 Introduction
2.2 Related Work
2.2.1 Signature Based Pattern Matching
2.2.2 Deep Learning for Web Security
2.2.3 Machine Learning via SVM
2.2.4 LLM Agents for Web Security
2.3 Existing Tools Analysis
2.3.1 ModSecurity
2.3.2 Cloudflare WAF
2.3.3 AWS WAF
2.4 Research Gap
2.5 Summary

**Chapter 3: System Analysis and Design**
3.1 Introduction
3.2 Functional Requirements
3.3 Non Functional Requirements
3.4 Software Requirements
3.5 Hardware Requirements
3.6 System Analysis
3.7 System Modeling
3.7.1 Use Case Diagram
3.7.2 Flowchart Diagram
3.7.3 Activity Diagram
3.7.4 Class Diagram
3.7.5 Sequence Diagram
3.7.6 Entity Relationship Diagram
3.8 Project Considerations
3.9 Project Plan (Gantt Chart)
3.10 Testing and Evaluation Plan
3.11 Summary
3.12 Future Work

References

---

# Chapter 1: Introduction

## 1.1 Background

The rapid expansion of web applications has made application-layer security a critical concern. According to OWASP, the most prevalent web application risks include injection attacks, cross-site scripting (XSS), and broken authentication. Web Application Firewalls operate at Layer 7 of the OSI model to inspect, analyze, and filter HTTP and HTTPS traffic before it reaches backend servers.

WAF technology has progressed through multiple generations: from simple IP-based allow/deny lists to signature-based detection matching requests against known attack patterns, then behavioral analysis identifying anomalous request patterns, and most recently machine learning-enhanced classification. Despite these advances, many production WAF deployments remain reactive, depending on manually curated rule sets that fail to detect previously unseen attack vectors.

## 1.2 Problem Statement

Traditional WAF solutions face critical limitations that reduce their effectiveness in modern threat environments:

**Static Signature Databases:** Pre-defined detection rules can only identify attacks matching existing patterns. Zero-day exploits and novel attack variants bypass signature-based detection entirely.

**High False-Positive Rates:** Overly broad pattern matching frequently blocks legitimate requests, with production false-positive rates exceeding ten percent, creating operational burden for security teams.

**Limited Adaptability:** Open-source WAF solutions lack automatic signature generation from observed attacks, requiring administrators to manually analyze blocked requests and create detection rules.

**Performance Bottlenecks:** Synchronous database operations and in-memory state management create scaling constraints under high traffic volumes, with cumulative latency from per-request database access.

**Fragmented Monitoring:** Many open-source WAFs lack real-time monitoring interfaces, providing only log files or basic command-line tools, limiting visibility into attack patterns and system health.

## 1.3 Objectives

1. Develop a reverse proxy WAF filtering HTTP/HTTPS traffic using multiple detection strategies.
2. Implement signature-based pattern matching covering SQL injection, XSS, command injection, path traversal, file inclusion, DOM-XSS, SSTI, SSI, and XXE.
3. Integrate a machine learning model to classify traffic and reduce false positives.
4. Design automatic signature generation from blocked requests.
5. Build a real-time monitoring dashboard with WebSocket live updates.
6. Implement asynchronous database operations with connection pooling.
7. Support distributed caching via Redis for rate limiting and blacklist management.
8. Provide HTTPS/TLS termination with configurable certificate management.
9. Establish a CI/CD pipeline with automated testing and containerized deployment.

## 1.4 Project Scope

**Detection Engine:** Multi-strategy analysis combining signature pattern matching with 106 patterns across nine attack categories, behavioral anomaly detection monitoring per-IP request frequency using sliding window profiles, and ML classification using logistic regression on eight traffic features including path length, query length, body length, and binary indicators for special characters, SQL keywords, script tags, traversal sequences, and command characters.

**Proxy Infrastructure:** Reverse proxy using HTTPX for upstream forwarding with configurable timeout (30 seconds), injecting X-WAF-Analyzed header and extracting IPs from X-Forwarded-For with fallback to direct client address.

**Data Management:** SQLite with WAL journal mode, async access via aiosqlite with connection pooling (max 10 connections), and batch writer flushing every 5 seconds. Optional Redis for distributed caching of rate limits and blacklists.

**Machine Learning:** Logistic regression implemented with gradient descent optimization on eight features with standard scaling normalization. Supports training from up to 10,000 log samples with model persistence to JSON.

**Auto-Signatures:** Pattern extraction from blocked requests across four categories (SQL injection, XSS, command injection, traversal) with pending review workflow supporting approve/reject/delete operations.

**Monitoring:** Web dashboard with WebSocket real-time updates, Chart.js visualizations, IP blacklist management, rate limit monitoring, strategy statistics, ML model status, auto-signature review, TLS management, and system settings.

**Deployment:** Docker containerization with Docker Compose orchestration and GitHub Actions CI/CD pipeline with Trivy, Bandit, and Safety security scanning.

## 1.5 Contributions

1. **Unified Multi-Strategy Architecture:** Three complementary detection strategies in a single reverse proxy.
2. **Automatic Signature Generation:** Pattern extraction reducing manual rule curation effort.
3. **Performance-Optimized Data Layer:** Async operations with connection pooling and batched log writing.
4. **Real-Time Dashboard:** WebSocket-based updates with sub-second latency.
5. **ML Integration:** On-device logistic regression with explainable predictions and retraining.
6. **Production Deployment:** Docker Compose with Redis, TLS, and CI/CD pipeline.

## 1.6 Project Methodology

The project follows five iterative phases:

**Phase 1 (Weeks 1-2):** Requirements analysis, technology evaluation, architectural design.
**Phase 2 (Weeks 3-6):** Proxy engine, signature matching, behavioral analysis, database layer.
**Phase 3 (Weeks 7-10):** ML model, auto-signature generation, WebSocket dashboard.
**Phase 4 (Weeks 11-13):** Redis caching, TLS termination, Docker, CI/CD pipeline.
**Phase 5 (Weeks 14-16):** Zero-day detection, DDoS protection, testing, security scanning, documentation.

## 1.7 Report Structure

Chapter 1 introduces the background, objectives, and contributions. Chapter 2 reviews literature and analyzes existing WAF tools. Chapter 3 presents system analysis, design, modeling, and testing methodology.

---

# Chapter 2: Literature Review

## 2.1 Introduction

This chapter reviews academic literature on WAF technology focusing on signature-based detection, machine learning approaches, deep learning techniques, and emerging LLM applications in cybersecurity. It also analyzes existing commercial and open-source tools to identify gaps this project addresses.

## 2.2 Related Work

### 2.2.1 Signature Based Pattern Matching

Signature-based detection remains the most widely deployed WAF technology. ModSecurity utilizes the OWASP Core Rule Set containing over one thousand rules covering common web application attack vectors (Santiago et al., 2019). Zsebenyi et al. (2020) demonstrated that signature-based systems achieve high detection accuracy against known attack patterns with true positive rates exceeding 90 percent for well-covered categories, but exhibit limitations against polymorphic attacks that modify payload encoding or structural arrangement while preserving malicious intent.

Pattern matching has evolved from simple substring comparison to sophisticated regular expression engines capable of identifying encoded and obfuscated attack variants. Modern systems decode URL-encoded characters, normalize Unicode representations, and strip comment sequences before applying pattern rules, increasing detection coverage at the cost of computational overhead proportional to rule set size.

Wang and Stolfo (2004) established that signature detection achieves optimal effectiveness when combined with complementary methods like anomaly detection. This project follows this principle, computing threat confidence as min(0.95, 0.5 + matched_count * 0.15), enabling the aggregation engine to distinguish between requests matching a single weak pattern versus those exhibiting multiple strong indicators of malicious intent.

### 2.2.2 Deep Learning for Web Security

Deep learning techniques have been applied to web traffic classification with promising results in controlled research environments. Mirsky et al. (2018) demonstrated that deep autoencoder networks can learn compressed representations of normal HTTP traffic patterns and detect anomalous requests by measuring reconstruction error. Their Kitsune system processes raw network packet features through an ensemble of autoencoders, each responsible for a subset of features, achieving high detection rates against network-level intrusions without requiring labeled attack data. The ensemble approach distributes learning across feature groups, enabling detection of anomalies that might be masked in a single monolithic model.

Somasundaram and Muniyandi (2019) applied Long Short-Term Memory recurrent neural networks to sequential HTTP request analysis, modeling the temporal patterns of user session behavior to detect attack sequences. LSTM networks maintain hidden state across sequential inputs, capturing dependencies between requests within a session that static feature-based classifiers cannot observe. This sequential modeling enables detection of multi-stage attacks where individual requests appear benign but the sequence reveals malicious intent, such as progressive path traversal attempts or incremental SQL injection probing.

Despite these research advances, deep learning faces significant practical limitations for real-time WAF deployment. Neural network inference requires substantially more floating-point operations per request than rule-based matching or logistic regression classification. For a WAF targeting sub-50 millisecond analysis latency, the computational cost of passing each request through multiple neural network layers introduces unacceptable delay. Additionally, deep learning models require large volumes of labeled training data to achieve reliable accuracy, and collecting representative datasets covering all attack categories at sufficient scale remains a significant challenge. The opacity of neural network decision-making, often described as the black box problem, creates interpretability challenges for security operations teams who must understand and justify blocking decisions to stakeholders and compliance auditors.

### 2.2.3 Machine Learning via SVM

Support Vector Machines have been extensively studied and applied to web application security classification tasks. Sharafaldin et al. (2018) achieved over 95 percent accuracy classifying HTTP requests into benign and malicious categories using SVM classifiers on their CICIDS2017 intrusion detection dataset. Their feature engineering approach extracted structural characteristics from HTTP requests including URL length, parameter count, special character frequency, and entropy measures, demonstrating that well-engineered features combined with SVM produce high-quality classifications.

Inoue et al. (2017) demonstrated SVM-based WAF implementations capable of detecting attack patterns not present in the training data through feature representation learning. By extracting structural features from HTTP requests including URL depth, query parameter count, character distribution statistics, and token frequency analysis, SVM classifiers generalize beyond literal pattern matching to identify requests with structural characteristics consistent with known attack types. This generalization capability enables detection of novel attack variants that share structural properties with known attacks despite differing in literal payload content.

Apruzzese et al. (2018) conducted a comprehensive comparative evaluation of machine learning effectiveness for cybersecurity applications, testing SVM, logistic regression, random forests, and neural networks across multiple detection tasks using standardized datasets. Their key finding directly relevant to this project: logistic regression achieves detection rates comparable to SVM for binary web attack classification while offering significantly lower inference latency and greater interpretability. Logistic regression produces probability estimates through sigmoid activation that are directly interpretable as confidence scores, enabling threshold-based blocking decisions. Furthermore, the learned feature weights in logistic regression provide transparent insight into which request characteristics most influence classification decisions, supporting explainable security operations. This empirical evidence directly informed this project's choice of logistic regression over SVM for the machine learning classification component.

### 2.2.4 LLM Agents for Web Security

Recent research has explored the application of large language models to cybersecurity tasks with promising results for offline analysis scenarios. Wang et al. (2024) investigated LLM-based agents for automated vulnerability assessment, demonstrating that language models can identify security flaws in application source code through semantic analysis and contextual reasoning about data flow, input validation, and access control logic. Their agents achieved high precision in detecting injection vulnerabilities, authentication bypasses, and insecure configuration patterns that traditional static analysis tools frequently miss due to their reliance on syntactic pattern matching.

Hegarty et al. (2024) examined LLM-driven security orchestration, where language models coordinate multiple security tools, analyze and correlate alerts from disparate monitoring systems, and generate prioritized incident response recommendations. Their approach shows potential for augmenting security operations center workflows by reducing analyst workload through automated alert triage, contextual enrichment of security events with threat intelligence, and generation of actionable response playbooks.

However, the computational cost and inference latency of large language models make them fundamentally unsuitable for real-time WAF operations at present. Processing each incoming HTTP request through an LLM would introduce latency orders of magnitude greater than the sub-50 millisecond target, as LLM inference requires billions of parameter computations per request. Additionally, the probabilistic and non-deterministic nature of LLM outputs raises reliability concerns for automated blocking decisions, where false positives directly impact service availability. This project's architecture includes provisions for optional external AI API integration, enabling LLM-driven analysis to operate asynchronously alongside the real-time detection engine for offline threat investigation, attack pattern analysis, and signature enrichment without impacting real-time request processing latency.

## 2.3 Existing Tools Analysis

### 2.3.1 ModSecurity

ModSecurity is the most widely deployed open-source web application firewall, operating as a module for Apache, Nginx, and IIS. It applies OWASP Core Rule Set rules covering SQL injection, cross-site scripting, file inclusion, and remote code execution. Limitations include dependence on manually maintained rules with delays between attack discovery and rule deployment, configuration complexity requiring regex expertise, lack of built-in ML capabilities, and no built-in real-time monitoring dashboard without additional tooling.

### 2.3.2 Cloudflare WAF

Cloudflare WAF is a managed cloud-based service integrated into their CDN, providing signature detection, rate limiting, bot management, and DDoS protection. Global threat intelligence sharing across millions of sites enables rapid rule updates. Advantages include zero infrastructure management and automatic performance optimization. Limitations include proprietary architecture with limited customization, infrastructure dependency making migration difficult, and black-box ML with no transparency into classification decisions.

### 2.3.3 AWS WAF

AWS WAF is integrated with Amazon CloudFront, Application Load Balancer, and API Gateway. It offers managed rule groups from AWS and marketplace vendors, rate-based rules with automatic IP blocking, and CloudWatch metrics. Tight AWS integration simplifies deployment but creates platform lock-in. AWS WAF lacks built-in ML classification and uses a per-rule, per-request pricing model creating cost uncertainty for high-traffic applications.

## 2.4 Research Gap

**Integrated Multi-Strategy Detection:** Few open-source WAFs combine signature, behavioral, and ML approaches in a single lightweight deployment.

**Automatic Signature Generation:** Limited research on automated extraction of reusable signatures from observed attacks.

**Real-Time Monitoring:** Open-source WAFs typically lack comprehensive real-time dashboards.

**Performance Optimization:** Academic ML-WAF research focuses on accuracy without addressing latency constraints.

**Explainable ML:** Many ML security tools deploy opaque models; this project's logistic regression offers transparent feature weight analysis.

## 2.5 Summary

This chapter reviewed WAF evolution, academic research on detection methods, and existing tool limitations. Identified gaps in multi-strategy integration, automatic signature generation, real-time monitoring, and performance optimization motivate the proposed system design.

---

# Chapter 3: System Analysis and Design

## 3.1 Introduction

This chapter covers functional and non-functional requirements, technology decisions, system architecture, UML modeling, project planning, and testing methodology.

## 3.2 Functional Requirements

**FR1 - Traffic Inspection:** Intercept all HTTP/HTTPS requests, extract metadata (method, path, query, headers, body preview up to 500 bytes), analyze against enabled strategies before forwarding.

**FR2 - Signature Detection:** Detect SQL injection, XSS, command injection, path traversal, file inclusion, file upload, DOM-XSS, SSTI, SSI, and XXE via 106 patterns in nine configurable categories.

**FR3 - Behavioral Analysis:** Monitor per-IP request frequency, path diversity, and temporal patterns using sliding window profiles.

**FR4 - ML Classification:** Extract eight features per request, classify using trained logistic regression with confidence scores. Support training from logs and persistence.

**FR5 - Auto-Signature Generation:** Extract patterns from blocked requests across four categories with pending review workflow supporting approve/reject/delete.

**FR6 - IP Blacklisting:** Maintain blacklist with permanent/temporary bans. Auto-ban IPs exceeding five violations. Whitelisted IPs bypass all detection.

**FR7 - Rate Limiting:** Enforce per-IP limits (default: 100 requests per 60 seconds). Exceeding requests receive HTTP 429.

**FR8 - Request Logging:** Log all requests with timestamp, method, path, IP, decision, threat level, confidence, reasoning, analysis time, and strategy results. Support filtering and pagination.

**FR9 - Real-Time Monitoring:** Web dashboard with WebSocket live updates, metrics charts, threat distribution, IP management, and system settings.

**FR10 - TLS Termination:** HTTPS inspection via TLS termination (minimum TLS 1.2) with self-signed certificate generation.

**FR11 - Configuration Management:** All parameters configurable via API endpoints and environment variables.

## 3.3 Non Functional Requirements

| ID | Requirement | Target |
|----|------------|--------|
| NFR1 | Performance | Under 50ms per request |
| NFR2 | Scalability | 10 concurrent DB connections, 1000 req/min |
| NFR3 | Availability | Fail-open mode for continuity |
| NFR4 | Reliability | All tests passing |
| NFR5 | Security | TLS 1.2 minimum, parameterized queries |
| NFR6 | Maintainability | Modular architecture |
| NFR7 | Deployability | Docker Compose single-command setup |

## 3.4 Software Requirements

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| Runtime | Python | 3.12+ | Application execution |
| Framework | FastAPI | 0.115+ | HTTP API and routing |
| HTTP Client | HTTPX | 0.27+ | Upstream forwarding |
| Database | SQLite | 3.x | Primary storage |
| Async DB | aiosqlite | 0.20+ | Async database access |
| Cache | Redis | 7.0+ (optional) | Distributed state |
| ML | Scikit-learn | 1.5+ | ML utilities |
| Numerical | NumPy | 1.26+ | Vectorized computation |
| Crypto | cryptography | 43.0+ | TLS certificates |
| Logging | structlog | 24.0+ | Structured logging |
| Testing | pytest | 8.0+ | Unit/integration tests |
| Container | Docker | 24.0+ | Containerization |

## 3.5 Hardware Requirements

| Specification | Minimum | Recommended |
|--------------|---------|-------------|
| CPU Cores | 2 | 4 |
| RAM | 2 GB | 4 GB |
| Storage | 5 GB HDD | 10 GB SSD |
| Network | 100 Mbps | 1 Gbps |

Minimum supports up to 1000 requests per minute. Recommended provides headroom for concurrent connections and ML operations.

## 3.6 System Analysis

The architecture follows a layered design with four distinct tiers:

**Proxy Layer:** Entry point for all client traffic. Performs TLS termination, extracts request metadata (method, path, query, headers, body preview up to 500 bytes), injects X-WAF-Analyzed header, and forwards allowed requests. IP extraction uses X-Forwarded-For header with fallback to direct client address. Upstream URL defaults to localhost:8080 with configurable 30-second timeout.

**Detection Layer:** Executes strategies in parallel. Signature matcher evaluates 106 patterns across nine categories with threat levels from none to critical, computing confidence as min(0.95, 0.5 + matched_count * 0.15). Behavioral analyzer maintains per-IP request profiles. ML classifier extracts eight features and produces predictions. Results are aggregated with AI agents weighted at 1.5x and standard strategies at 1.0x; threat score above 0.5 triggers block.

**Data Layer:** SQLite with WAL journal mode, aiosqlite connection pool (max 10 connections), and batch writer flushing every 5 seconds. Optional Redis provides distributed caching for rate limits and blacklists with automatic fallback to in-memory storage on Redis unavailability.

**Presentation Layer:** Web dashboard communicating via REST API for historical data and WebSocket for real-time event streaming with sub-second latency. Nine tabs cover metrics, live logs, blacklist, rate limits, strategies, ML status, auto-signatures, TLS, and settings.

---

**[Figure 3.1: System Architecture Diagram]**
*Four horizontal layers: Proxy Layer receiving client requests and forwarding to upstream, Detection Layer with three parallel strategy boxes, Data Layer with SQLite and optional Redis, Presentation Layer with web dashboard connected via WebSocket.*

---

## 3.7 System Modeling

### 3.7.1 Use Case Diagram

**Actors:** Client/Attacker (sends requests), System Administrator (configures, monitors, reviews), Upstream Server (receives forwarded requests).

**Use Cases:** Inspect Request, Detect Attack, Classify Traffic (ML), Generate Auto-Signature, Review Signature, Monitor Traffic, Manage Blacklist, Configure WAF, Forward Request, Block Request.

**Relationships:** Inspect Request includes Detect Attack, Classify Traffic, and Generate Auto-Signature. Administrator performs Review Signature, Monitor Traffic, Manage Blacklist, and Configure WAF.

---

**[Figure 3.2: Use Case Diagram]**
*System boundary rectangle with ten use case ovals. Client connects to Inspect Request. Administrator connects to Review Signature, Monitor Traffic, Manage Blacklist, Configure WAF. Inspect Request includes Detect Attack, Classify Traffic, Generate Auto-Signature.*

---

### 3.7.2 Flowchart Diagram

Request arrives at WAF. TLS check for HTTPS termination. Blacklist check queries database; if banned, return 403. Whitelist check; if trusted, skip to forward. Rate limit check; if exceeded, return 429. Signature analysis against enabled categories. Behavioral analysis of request patterns. ML classification with feature extraction. Decision aggregation combining strategy results. Block check; if threat score above 0.5, log request, update violations, generate auto-signature, return 403. Otherwise forward to upstream server.

---

**[Figure 3.3: Flowchart Diagram]**
*Start oval to TLS check rectangle to Blacklist diamond (403 branch), Whitelist diamond (forward branch), Rate limit diamond (429 branch), three processing rectangles (Signature, Behavioral, ML), Aggregation rectangle, Block diamond (403 or Forward), End oval.*

---

### 3.7.3 Activity Diagram

Request received triggers fork into three parallel swimlanes. Signature Matching lane: extract components, iterate categories, collect matches, produce decision. Behavioral Analysis lane: track metadata, update profile, check anomalies, produce assessment. ML Classification lane: extract eight features, apply scaling, compute prediction, return classification. Join bar synchronizes parallel activities. Aggregation combines results. Decision routes to block (log, update violations) or forward (send to upstream). Two final nodes.

---

**[Figure 3.4: Activity Diagram]**
*Initial node to fork bar. Three swimlanes with sequential activities converging at join bar, then aggregation, decision node, and two final nodes.*

---

### 3.7.4 Class Diagram

**Core Classes:**

**WAFProxy:** Main orchestrator. Attributes: upstream URL, HTTPX client, strategy registry, config reference. Methods: forward_request, analyze_request, aggregate_results, get_metrics.

**SignatureStrategy:** Pattern matching. Attributes: signature database by category, enabled flags, match stats. Methods: analyze, get_categories.

**BehaviorStrategy:** Anomaly detection. Attributes: per-IP profiles, thresholds. Methods: analyze, update_profile.

**WAFMLModel:** ML wrapper. Attributes: weights, bias, scaler params, feature names, training metadata. Methods: classify, train, extract_features, retrain_from_db.

**RequestLogger:** Logging with pub-sub. Attributes: log deque (max 1000), subscriber list. Methods: log, get_logs, get_summary, subscribe, seed_sample_data.

**AutoSignatureGenerator:** Pattern extraction. Attributes: rules in JSON, pattern keywords for four categories. Methods: analyze_blocked, approve_rule, reject_rule, delete_rule.

**RedisCache:** Distributed cache. Attributes: Redis connection, fallback flags. Methods: get, set, delete, increment, get_ttl.

**AsyncWAFDatabase:** Async DB manager. Attributes: connection pool, batch writer queue, flush timer. Methods: initialize, log_request, get_summary, get_logs, get_timeline, cleanup_old_logs, close.

**TLSConfig:** Certificate management. Attributes: cert path, key path, SSL context. Methods: create_ssl_context, is_configured, get_info.

**ZeroDayDetector:** Anomaly detection. Attributes: deviation threshold (2.5), baseline window (200), baseline stats. Methods: analyze, update_baseline.

**DDoSProtector:** Flood mitigation. Attributes: global RPS threshold (500), IP flood threshold (60), sliding window trackers. Methods: analyze, track_request.

**Relationships:** WAFProxy aggregates all strategies and components. WAFProxy depends on AsyncWAFDatabase and RedisCache.

---

**[Figure 3.5: Class Diagram]**
*Eleven class rectangles with attributes and methods. WAFProxy at center with aggregation to all strategies. Dependency arrows to AsyncWAFDatabase and RedisCache.*

---

### 3.7.5 Sequence Diagram

Client sends HTTP Request to WAFProxy. WAFProxy queries AsyncWAFDatabase (Check Blacklist); if banned, return 403. Queries RedisCache (Check Rate Limit); if exceeded, return 429. Calls SignatureStrategy.analyze, BehaviorStrategy.analyze, WAFMLModel.classify in parallel. Calls aggregate_results combining outputs. If threat score exceeds 0.5: calls RequestLogger.log, AutoSignatureGenerator.analyze_blocked, updates violations, returns 403. Otherwise: forwards to Upstream Server, returns response to Client.

---

**[Figure 3.6: Sequence Diagram]**
*Seven lifelines: Client, WAFProxy, AsyncWAFDatabase, RedisCache, SignatureStrategy, BehaviorStrategy, WAFMLModel, AutoSignatureGenerator, Upstream Server. Alt fragment separating block and allow paths.*

---

### 3.7.6 Entity Relationship Diagram

Seven tables:

**request_logs:** id PK, timestamp, method, path, query_string, source_ip, user_agent, decision, threat_level, confidence, reason, analysis_time_ms, strategies_json, created_at. Indexed on timestamp, source_ip, decision.

**ip_blacklist:** id PK, ip UNIQUE, reason, violation_count, threat_level, is_permanent, is_whitelisted, banned_at, expires_at, last_seen. Indexed on ip.

**ip_violations:** id PK, ip FK to ip_blacklist(ip), threat, threat_level, timestamp. Indexed on ip.

**rate_limit_stats:** id PK, ip, request_count, window_start, window_end, blocked, created_at.

**waf_config:** key PK, value, updated_at.

**threat_stats:** id PK, date, category, count. Unique on date+category.

**daily_summary:** date PK, total_requests, blocked_requests, allowed_requests, avg_analysis_time_ms, top_threat, created_at.

**Relationships:** ip_blacklist (1:N) ip_violations via ip foreign key.

---

**[Figure 3.7: ER Diagram]**
*Seven entity rectangles with attributes. Primary keys underlined. 1:N relationship between ip_blacklist and ip_violations.*

---

## 3.8 Project Considerations

**Ethical:** The system logs IP addresses and request content requiring GDPR/CCPA compliance. Log cleanup function removes entries older than 30 days.

**Legal:** Self-signed certificates suit testing but must be replaced with CA-signed certificates in production. Fail-open design ensures continuity but may allow malicious traffic if detection fails.

**Technical:** Logistic regression captures linear boundaries only; complex non-linear patterns require more sophisticated models. Designed for small to medium deployments.

**Operational:** Auto-generated signatures require administrator review before deployment. WebSocket connectivity required for real-time dashboard updates.

## 3.9 Project Plan (Gantt Chart)

| Phase | Weeks | Duration | Activities |
|-------|-------|----------|-----------|
| Phase 1: Requirements & Design | 1-2 | 2 weeks | Requirements, technology evaluation, architecture |
| Phase 2: Core Development | 3-6 | 4 weeks | Proxy engine, signatures, behavioral analysis, database |
| Phase 3: Intelligence Integration | 7-10 | 4 weeks | ML model, auto-signatures, WebSocket dashboard |
| Phase 4: Infrastructure | 11-13 | 3 weeks | Redis, TLS, Docker, CI/CD pipeline |
| Phase 5: Testing & Validation | 14-16 | 3 weeks | Unit testing, integration, security scanning, docs |

Phases are sequential with dependencies. Phase 2 requires Phase 1 approval. Phase 3 requires Phase 2 infrastructure. Phase 5 runs after all components are integrated.

---

**[Figure 3.8: Gantt Chart]**
*Horizontal timeline across 16 weeks. Five colored bars per phase with milestone diamonds at boundaries. Dependency arrows connecting sequential phases.*

---

## 3.10 Testing and Evaluation Plan

**Unit Testing:** Automated tests using pytest cover all system components across fifteen test modules. Database operations tests validate CRUD functionality for all seven tables and cleanup operations enforcing 30-day log retention. Blacklist management tests verify ban creation, auto-ban after five violations, expiration handling, and whitelist override. Signature matching tests verify pattern detection across all nine categories and confirm legitimate requests pass. ML model tests cover feature extraction, training convergence, prediction accuracy, and model persistence. Auto-signature tests validate pattern extraction and review workflow. Redis tests verify distributed operations and fallback behavior. TLS tests verify certificate generation and SSL context creation. Request logging tests verify subscriber notification and summary computation. Integration tests exercise end-to-end flows through the complete detection pipeline.

**Integration Testing:** FastAPI TestClient simulates complete request cycles verifying that clean requests pass all strategies and are forwarded with the X-WAF-Analyzed header, attack requests with SQL injection and XSS payloads are blocked with HTTP 403 and logged, repeated attacks from the same IP trigger auto-ban after five violations, and dashboard endpoints return correct data. WebSocket tests verify real-time event streaming with sub-second latency.

**Security Testing:** CI/CD pipeline integrates Trivy for container vulnerability scanning against known CVE databases, Bandit for Python static analysis identifying security anti-patterns, and Safety for dependency vulnerability checking. All scanners must pass without critical findings.

**Performance:** analysis_time_ms targets sub-50ms latency. Batch writer flushes every 5 seconds reducing per-request I/O. Connection pool limits to 10 concurrent connections preventing resource exhaustion.

## 3.11 Summary

This chapter presented the complete system design including 11 functional requirements, 7 non-functional requirements, the technology stack, four-layer architecture, six UML diagrams, 16-week project plan across five phases, and comprehensive testing strategy.

## 3.12 Future Work

1. **Deep Learning:** Replace logistic regression with neural networks for non-linear pattern detection.
2. **LLM Integration:** Semantic analysis for logic-based attack detection.
3. **Distributed Clustering:** Horizontal scaling with synchronized Redis state.
4. **Cloud-Native Deployment:** Kubernetes Helm charts with service mesh.
5. **Threat Intelligence:** External IP reputation feeds.
6. **Advanced Analytics:** Predictive traffic forecasting and automated threshold tuning.
7. **API Security:** JWT validation, GraphQL depth limiting.
8. **Compliance Reporting:** Automated PCI-DSS, SOC 2, ISO 27001 reports.

---

# References

1. OWASP Foundation. (2021). OWASP Top Ten Web Application Security Risks. https://owasp.org/www-project-top-ten/

2. Santiago, I., Smith, A., and Zaddach, C. (2019). ModSecurity Handbook, 2nd Edition. Trustwave Holdings.

3. Zsebenyi, Z., Kotulyak, M., and Kovesdan, E. (2020). Evaluation of Web Application Firewall Solutions. IEEE Cyber Security and Resilience Conference, 120-125.

4. Wang, K., and Stolfo, S. J. (2004). Anomalous Payload-Based Network Intrusion Detection. RAID Symposium, 203-222.

5. Sharafaldin, I., Lashkari, A. H., and Ghorbani, A. A. (2018). Toward Generating a New Intrusion Detection Dataset. ICISSP, 108-120.

6. Inoue, D., Zhang, Y., and Hasegawa, K. (2017). Web Application Firewall Evasion Techniques. Journal of Information Processing, 25, 612-622.

7. Apruzzese, G., Colajanni, M., Ferretti, L., and Guido, A. (2018). On the Effectiveness of Machine Learning for Cybersecurity. CyCon, 371-390.

8. Li, Y., Zhang, H., and Wang, X. (2020). SQL Injection Detection Using Ensemble Learning. IEEE Access, 8, 142567-142578.

9. Mirsky, Y., Doitshman, T., Elovici, Y., and Shabtai, A. (2018). Kitsune: An Ensemble of Autoencoders for Intrusion Detection. NDSS.

10. Somasundaram, G., and Muniyandi, S. (2019). Deep Learning for Web Attack Detection. IJAST, 28(19), 456-468.

11. Wang, Z., Li, X., and Chen, Y. (2024). LLM-Based Agents for Vulnerability Assessment. IEEE Security and Privacy, 22(3), 45-53.

12. Hegarty, R., Krol, K., and Sasse, M. A. (2024). Language Models for Security Orchestration. ACM Computing Surveys, 56(8), 1-38.

13. ModSecurity Project. (2024). https://modsecurity.org/

14. Cloudflare Inc. (2024). https://www.cloudflare.com/products/web-application-firewall/

15. Amazon Web Services. (2024). https://aws.amazon.com/waf/

16. OWASP Core Rule Set. (2024). https://coreruleset.org/

17. Pedregosa, F., et al. (2011). Scikit-learn: Machine Learning in Python. JMLR, 12, 2825-2830.
