# 推荐的服务条款与隐私政策 / Recommended Terms of Service & Privacy Policy

> 本文件包含两份建议模板：**服务条款（Terms of Service / ToS）** 与 **隐私政策（Privacy Policy）**。  
> This document contains two recommended templates: **Terms of Service (ToS)** and **Privacy Policy**.  
>
> 每份模板均以 **HTML 富文本** 形式给出，您可以直接复制到您的网站 / 管理后台中使用，并根据实际情况调整占位符（如 `【团队名称】`、`【联系邮箱】`、`【生效日期】` 等）。  
> Each template is provided as **rich-text HTML** so you can paste it directly into your site / admin panel. Please adjust placeholders such as `【Team Name】`, `【Contact Email】`, `【Effective Date】` as appropriate.  
>
> ⚠️ **法律声明 / Legal Notice**：本文件为**通用参考模板**，不构成法律意见。正式发布前建议由当地执业律师审阅，以确保符合您所在司法管辖区（中国大陆 / 欧盟 GDPR / 美国 CCPA 等）的法律法规。  
> This document is a **general reference template** and does **not** constitute legal advice. Before publishing, please have it reviewed by a qualified lawyer in your jurisdiction (e.g. PRC / EU GDPR / US CCPA).

---

## 一、服务条款 / Terms of Service

以下为建议的服务条款 HTML 源码。  
The following is the recommended HTML source of the Terms of Service.

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8" />
    <title>服务条款 / Terms of Service</title>
    <style>
        body { font-family: "Helvetica Neue", "PingFang SC", "Microsoft YaHei", Arial, sans-serif; line-height: 1.75; color: #222; max-width: 960px; margin: 0 auto; padding: 32px 24px; }
        h1 { font-size: 26px; border-bottom: 2px solid #1677ff; padding-bottom: 8px; }
        h2 { font-size: 20px; color: #1677ff; margin-top: 36px; }
        h3 { font-size: 16px; margin-top: 24px; }
        .zh { color: #111; }
        .en { color: #555; font-size: 14px; display: block; margin-top: 4px; font-style: italic; }
        ul, ol { padding-left: 24px; }
        li { margin-bottom: 8px; }
        .notice { background: #fffbe6; border-left: 4px solid #faad14; padding: 12px 16px; margin: 16px 0; }
        .danger { background: #fff1f0; border-left: 4px solid #ff4d4f; padding: 12px 16px; margin: 16px 0; }
        .highlight { background: #e6f4ff; border-left: 4px solid #1677ff; padding: 12px 16px; margin: 16px 0; }
        table { border-collapse: collapse; width: 100%; margin: 16px 0; }
        th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; }
        th { background: #fafafa; }
        .meta { color: #888; font-size: 13px; }
    </style>
</head>
<body>

<h1>服务条款 <span class="en">Terms of Service</span></h1>

<p class="meta">
    生效日期 / Effective Date：<strong>2026-01-22</strong><br />
    最后更新 / Last Updated：<strong>2026-04-22</strong><br />
    服务提供方 / Service Provider：<strong>Team Transmtf</strong>
</p>

<div class="highlight">
    <p>
        <span class="zh">欢迎使用 <strong>Transmtf系列产品</strong>（以下简称"<strong>本服务</strong>"）。在使用本服务之前，请您<strong>完整、仔细</strong>地阅读本《服务条款》（以下简称"<strong>本条款</strong>"）。一旦您注册、登录或以任何方式使用本服务，即视为您已阅读、理解并同意本条款的全部内容。</span>
        <span class="en">Welcome to <strong>Transmtf series of products</strong> (the "<strong>Service</strong>"). Please read these Terms of Service (the "<strong>Terms</strong>") carefully before using the Service. By registering, logging in, or otherwise using the Service, you acknowledge that you have read, understood, and agreed to these Terms in full.</span>
    </p>
</div>

<!-- ===================== 1. 账号与团队 ===================== -->
<h2>1. 账号与团队 <span class="en">Accounts & Teams</span></h2>

<h3>1.1 注册与身份 <span class="en">Registration & Identity</span></h3>
<ul>
    <li>
        <span class="zh">您应当使用<strong>真实、准确、完整</strong>的信息注册账号，并对账号下的所有行为负责。</span>
        <span class="en">You must register with <strong>truthful, accurate and complete</strong> information, and you are responsible for all activities occurring under your account.</span>
    </li>
    <li>
        <span class="zh">您应妥善保管账号及密码。若发现账号被盗用或存在安全风险，请立即通知我们。</span>
        <span class="en">You must keep your credentials safe. If you suspect any unauthorized use or security risk, notify us immediately.</span>
    </li>
</ul>

<h3>1.2 单一账号原则 <span class="en">Single-Account Principle</span></h3>
<div class="notice">
    <p>
        <span class="zh">原则上，<strong>每位自然人 / 每个组织只应注册并持有一个账号</strong>。未经我们<strong>事先书面授权</strong>，禁止以任何形式注册、使用、买卖或转让多个账号（包括但不限于：刷量、规避限制、薅取福利、伪装身份等）。</span>
        <span class="en">In principle, <strong>each individual or organization may register and hold only ONE account</strong>. Without our <strong>prior written authorization</strong>, you may not create, use, trade, or transfer multiple accounts for any purpose (including but not limited to: inflating metrics, circumventing restrictions, abusing promotions, or identity spoofing).</span>
    </p>
    <p>
        <span class="zh">若因业务需要（如测试、多品牌运营）确需多账号，请通过 <strong>contact@transmtf.com</strong> 申请白名单。</span>
        <span class="en">If multiple accounts are genuinely required (e.g. testing, multi-brand operation), please apply for a whitelist at <strong>contact@transmtf.com</strong>.</span>
    </p>
</div>

<h3>1.3 团队成员关系 <span class="en">Team Membership</span></h3>
<div class="highlight">
    <p>
        <span class="zh"><strong>我们不会仅因您与团队中其他成员之间的个人纠纷、人际关系或个人原因而封禁您的账号。</strong>您的账号独立于他人的行为。</span>
        <span class="en"><strong>We will NOT suspend or terminate your account solely due to personal disputes, interpersonal conflicts, or personal reasons involving other team members.</strong> Your account is treated independently of others' conduct.</span>
    </p>
    <p>
        <span class="zh">但是，若您的行为<strong>客观上损害了团队的合法利益</strong>（例如泄露团队机密、恶意破坏团队协作数据、对团队成员实施网络攻击或骚扰、违反团队内部规章等），我们<strong>有权暂停或停用您的账号</strong>，以保护其他成员及团队整体利益。</span>
        <span class="en">However, if your conduct <strong>objectively harms the legitimate interests of the team</strong> (e.g. leaking confidential information, maliciously damaging collaborative data, attacking or harassing other members, or violating internal team rules), we reserve the right to <strong>suspend or terminate your account</strong> to protect other members and the team as a whole.</span>
    </p>
    <p>
        <span class="zh">无论账号因何种原因被停用，<strong>您始终有权要求我们在合理期限内导出您在本系统中属于您个人的数据</strong>。这是您的<strong>法定权利</strong>，我们将在核实身份后，免费、及时地配合您完成数据导出（导出格式及范围详见《隐私政策》）。</span>
        <span class="en">Regardless of the reason for suspension or termination, <strong>you shall at all times retain the right to request an export of your personal data stored in the Service</strong> within a reasonable period. This is your <strong>statutory right</strong>. After verifying your identity, we will assist you with the export free of charge and in a timely manner (see the Privacy Policy for supported formats and scope).</span>
    </p>
</div>

<!-- ===================== 2. 用户行为规范 ===================== -->
<h2>2. 用户行为规范 <span class="en">Acceptable Use Policy</span></h2>

<p>
    <span class="zh">您在使用本服务时，承诺遵守所有适用的法律法规，并<strong>不得</strong>从事以下行为：</span>
    <span class="en">When using the Service, you agree to comply with all applicable laws and <strong>shall NOT</strong>:</span>
</p>

<ol>
    <li>
        <span class="zh">发布、传输任何违法、违规、侵权、色情、暴力、恐怖、歧视或虚假的内容；</span>
        <span class="en">Publish or transmit any illegal, infringing, pornographic, violent, terrorist, discriminatory, or false content;</span>
    </li>
    <li>
        <span class="zh">利用本服务从事欺诈、洗钱、传销、非法集资、赌博等违法活动；</span>
        <span class="en">Use the Service for fraud, money laundering, pyramid schemes, illegal fundraising, gambling, or other unlawful activities;</span>
    </li>
    <li>
        <span class="zh">未经授权访问、篡改、爬取、逆向、反编译本服务或其数据；</span>
        <span class="en">Access, modify, scrape, reverse-engineer, or decompile the Service or its data without authorization;</span>
    </li>
    <li>
        <span class="zh"><strong>以"安全测试 / 漏洞挖掘 / 渗透测试 / 红队演练"等任何名义</strong>，在未获得我们<strong>事先书面授权</strong>的情况下，对本服务及其基础设施实施扫描、探测、攻击、DDoS、暴力破解、SQL 注入、XSS、CSRF、越权访问等行为；</span>
        <span class="en">Conduct any scanning, probing, attack, DDoS, brute-forcing, SQL injection, XSS, CSRF, privilege escalation, or similar action against the Service or its infrastructure <strong>under the pretext of "security testing", "vulnerability research", "penetration testing", or "red-team exercises"</strong>, without our <strong>prior written authorization</strong>;</span>
    </li>
    <li>
        <span class="zh">使用自动化脚本、机器人、外挂、模拟器等工具超出正常使用量地访问本服务；</span>
        <span class="en">Use bots, scripts, cheats, or emulators to access the Service beyond normal usage limits;</span>
    </li>
    <li>
        <span class="zh">出售、出租、出借、分享账号，或将本服务转售给第三方；</span>
        <span class="en">Sell, lease, lend, or share your account, or resell the Service to any third party;</span>
    </li>
    <li>
        <span class="zh">任何其他可能损害我们或第三方合法权益的行为。</span>
        <span class="en">Any other act that may harm the legitimate rights of us or any third party.</span>
    </li>
</ol>

<div class="danger">
    <p>
        <span class="zh"><strong>关于"善意安全研究"的说明</strong>：我们<strong>欢迎并感谢</strong>负责任的安全研究人员。若您发现潜在漏洞，请通过 <strong>contact@transmtf.com</strong> 报告，我们将遵循"负责任披露（Responsible Disclosure）"流程。在获得我们书面许可前，<strong>任何主动攻击性的测试均视为违法行为</strong>，我们将保留追究法律责任的权利。</span>
        <span class="en"><strong>On "Good-Faith Security Research"</strong>: We welcome and appreciate responsible security researchers. If you discover a potential vulnerability, please report it to <strong>contact@transmtf.com</strong> so we can follow a Responsible Disclosure process. Without our prior written permission, <strong>any active/offensive testing is deemed illegal</strong>, and we reserve the right to pursue legal action.</span>
    </p>
</div>

<!-- ===================== 3. 知识产权 ===================== -->
<h2>3. 知识产权 <span class="en">Intellectual Property</span></h2>
<ul>
    <li>
        <span class="zh">本服务的软件、界面、文案、商标、Logo 等的知识产权归<strong>Team Transmtf</strong>或其权利人所有。未经授权，您不得复制、传播、修改或用于商业目的。</span>
        <span class="en">All intellectual property in the Service (software, UI, copy, trademarks, logos) belongs to <strong>Team Transmtf</strong> or its licensors. You may not copy, distribute, modify, or use them commercially without authorization.</span>
    </li>
    <li>
        <span class="zh">您上传到本服务的内容，其知识产权归您所有；您授予我们为提供、改进服务所必需的有限、非独占、可撤销的使用许可。</span>
        <span class="en">Content you upload remains yours. You grant us a limited, non-exclusive, revocable license to use it solely as necessary to provide and improve the Service.</span>
    </li>
</ul>

<!-- ===================== 4. 账号停用与数据导出 ===================== -->
<h2>4. 账号停用与数据导出 <span class="en">Account Termination & Data Export</span></h2>

<table>
    <thead>
    <tr>
        <th>情形 / Scenario</th>
        <th>我们的处理 / Our Action</th>
        <th>您的权利 / Your Right</th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td>您主动注销 / You initiate deletion</td>
        <td>在合理期限内注销账号并删除数据 / We will delete your account and data within a reasonable period</td>
        <td>注销前可随时导出数据 / You may export your data at any time before deletion</td>
    </tr>
    <tr>
        <td>团队个人纠纷 / Interpersonal team disputes</td>
        <td><strong>不会封禁</strong> / We will <strong>NOT</strong> suspend your account</td>
        <td>账号继续正常使用 / Continued normal use</td>
    </tr>
    <tr>
        <td>您的行为损害团队利益 / Your conduct harms team interests</td>
        <td>我们有权暂停或停用账号 / We may suspend or terminate the account</td>
        <td>仍可申请数据导出 / You still have the right to request data export</td>
    </tr>
    <tr>
        <td>违反本条款或法律 / Violation of the Terms or law</td>
        <td>我们有权停用账号，并可能追究法律责任 / We may terminate the account and may pursue legal action</td>
        <td>可申请属于您个人的合法数据 / You may request your own lawful personal data</td>
    </tr>
    </tbody>
</table>

<!-- ===================== 5. 免责声明与责任限制 ===================== -->
<h2>5. 免责声明与责任限制 <span class="en">Disclaimer & Limitation of Liability</span></h2>
<ul>
    <li>
        <span class="zh">本服务按"现状"提供。在法律允许的最大范围内，我们不对服务的适销性、特定用途适用性作出任何明示或默示担保。</span>
        <span class="en">The Service is provided "AS IS". To the maximum extent permitted by law, we disclaim all warranties of merchantability or fitness for a particular purpose.</span>
    </li>
    <li>
        <span class="zh">因不可抗力、网络故障、第三方原因等导致的服务中断或数据损失，我们在法律允许范围内免责。</span>
        <span class="en">We are not liable for service interruption or data loss caused by force majeure, network outages, or third-party causes, to the extent permitted by law.</span>
    </li>
</ul>

<!-- ===================== 6. 法律权利保留 ===================== -->
<h2>6. 法律权利保留 <span class="en">Reservation of Legal Rights</span></h2>
<div class="danger">
    <p>
        <span class="zh">对于任何违反本条款或侵犯我们合法权益的行为，<strong>我们保留通过民事诉讼、行政举报、刑事报案等一切法律手段追究相关责任的权利</strong>。本条款的任何未主张部分，不构成对该权利的放弃。</span>
        <span class="en">For any breach of these Terms or infringement of our legitimate rights, <strong>we reserve the right to pursue all available legal remedies, including civil litigation, administrative complaints, and criminal reporting</strong>. Any delay in enforcement shall not constitute a waiver.</span>
    </p>
</div>

<!-- ===================== 7. 条款变更 ===================== -->
<h2>7. 条款的变更 <span class="en">Changes to the Terms</span></h2>
<p>
    <span class="zh">我们可能会根据业务需要或法律变化修订本条款。重大变更将通过站内通知、邮件或公告的方式告知您。若您在变更生效后继续使用本服务，即视为接受修订后的条款。</span>
    <span class="en">We may update these Terms from time to time. Material changes will be notified via in-app notice, email, or public announcement. Continued use after the effective date constitutes acceptance of the revised Terms.</span>
</p>

<!-- ===================== 8. 适用法律 ===================== -->
<h2>8. 适用法律与争议解决 <span class="en">Governing Law & Dispute Resolution</span></h2>
<p>
    <span class="zh">本条款的订立、履行与解释适用 <strong>中华人民共和国</strong> 法律。因本条款引起的争议，双方应首先友好协商；协商不成的，任何一方均可向有管辖权的人民法院提起诉讼。</span>
    <span class="en">These Terms are governed by the laws of <strong>the People's Republic of China</strong>. Disputes shall first be resolved through friendly negotiation; failing that, either party may file suit in the competent court.</span>
</p>

<!-- ===================== 9. 联系我们 ===================== -->
<h2>9. 联系我们 <span class="en">Contact Us</span></h2>
<p>
    <span class="zh">如您对本条款有任何疑问、意见或投诉，请通过以下方式与我们联系：</span>
    <span class="en">For any questions, feedback, or complaints regarding these Terms, please contact us via:</span>
</p>
<ul>
    <li>Email：<strong>contact@transmtf.com</strong></li>
    <li>Security：<strong>contact@transmtf.com</strong></li>
</ul>

</body>
</html>
```

---

## 二、隐私政策 / Privacy Policy

以下为建议的隐私政策 HTML 源码。  
The following is the recommended HTML source of the Privacy Policy.

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8" />
    <title>隐私政策 / Privacy Policy</title>
    <style>
        body { font-family: "Helvetica Neue", "PingFang SC", "Microsoft YaHei", Arial, sans-serif; line-height: 1.75; color: #222; max-width: 960px; margin: 0 auto; padding: 32px 24px; }
        h1 { font-size: 26px; border-bottom: 2px solid #52c41a; padding-bottom: 8px; }
        h2 { font-size: 20px; color: #389e0d; margin-top: 36px; }
        h3 { font-size: 16px; margin-top: 24px; }
        .zh { color: #111; }
        .en { color: #555; font-size: 14px; display: block; margin-top: 4px; font-style: italic; }
        ul, ol { padding-left: 24px; }
        li { margin-bottom: 8px; }
        .highlight { background: #f6ffed; border-left: 4px solid #52c41a; padding: 12px 16px; margin: 16px 0; }
        .notice { background: #fffbe6; border-left: 4px solid #faad14; padding: 12px 16px; margin: 16px 0; }
        .danger { background: #fff1f0; border-left: 4px solid #ff4d4f; padding: 12px 16px; margin: 16px 0; }
        table { border-collapse: collapse; width: 100%; margin: 16px 0; }
        th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; vertical-align: top; }
        th { background: #fafafa; }
        .meta { color: #888; font-size: 13px; }
    </style>
</head>
<body>

<h1>隐私政策 <span class="en">Privacy Policy</span></h1>

<p class="meta">
    生效日期 / Effective Date：<strong>2026-01-22</strong><br />
    最后更新 / Last Updated：<strong>2026-04-22</strong><br />
    服务提供方 / Service Provider：<strong>Team Transmtf</strong>
</p>

<div class="highlight">
    <p>
        <span class="zh"><strong>核心承诺</strong>：您在我们团队 / 系统中的<strong>全部数据，在法律上均归属于您本人</strong>。未经您的<strong>明确授权</strong>或法律的强制要求，<strong>我们绝不会向任何第三方透露、出售、出租或交换您的数据</strong>。这是我们对您最基本、最重要的承诺。</span>
        <span class="en"><strong>Our Core Commitment</strong>: All data you generate within our team/system <strong>belongs to YOU as a matter of law</strong>. Without your <strong>explicit authorization</strong> or a legally binding requirement, <strong>we will NEVER disclose, sell, lease, or exchange your data with any third party</strong>. This is our most fundamental promise to you.</span>
    </p>
</div>

<!-- ===================== 1. 数据所有权 ===================== -->
<h2>1. 数据所有权 <span class="en">Data Ownership</span></h2>
<div class="highlight">
    <ul>
        <li>
            <span class="zh">您上传、生成或存储在本服务中的内容（"<strong>用户数据</strong>"）的<strong>所有权、著作权及相关权利</strong>均归您本人或您所代表的组织所有。</span>
            <span class="en">All content you upload, generate, or store in the Service (the "<strong>User Data</strong>") — including <strong>ownership and related rights</strong> — belongs to you or the organization you represent.</span>
        </li>
        <li>
            <span class="zh">我们仅作为<strong>受您委托的数据处理者 / 存储者</strong>，依据您的授权及本政策来处理用户数据。</span>
            <span class="en">We act solely as the <strong>processor/custodian entrusted by you</strong>, and we process User Data only in accordance with your authorization and this Policy.</span>
        </li>
        <li>
            <span class="zh"><strong>未经您的明确授权，我们不会向任何个人、组织或第三方披露、共享或转让您的数据</strong>。</span>
            <span class="en"><strong>We will not disclose, share, or transfer your data to any individual, organization, or third party without your explicit authorization.</strong></span>
        </li>
    </ul>
</div>

<!-- ===================== 2. 我们收集的信息 ===================== -->
<h2>2. 我们收集哪些信息 <span class="en">What We Collect</span></h2>
<table>
    <thead>
    <tr>
        <th>类别 / Category</th>
        <th>内容 / Contents</th>
        <th>目的 / Purpose</th>
        <th>法律依据 / Legal Basis</th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td>账户信息 / Account</td>
        <td>用户名、邮箱、加密后的密码、头像 / Username, email, hashed password, avatar</td>
        <td>身份识别与登录 / Authentication</td>
        <td>合同履行 / Performance of contract</td>
    </tr>
    <tr>
        <td>用户内容 / User Content</td>
        <td>文档、文件、聊天、任务、评论等 / Documents, files, chats, tasks, comments</td>
        <td>向您提供核心功能 / Provide core features</td>
        <td>合同履行 / Performance of contract</td>
    </tr>
    <tr>
        <td>设备与日志 / Device & Logs</td>
        <td>IP、UA、设备 ID、访问日志、错误日志 / IP, UA, device ID, access & error logs</td>
        <td>安全防护、故障排查、统计 / Security, troubleshooting, analytics</td>
        <td>合法利益 / Legitimate interests</td>
    </tr>
    <tr>
        <td>支付信息 / Payment</td>
        <td>订单号、支付金额（支付渠道直收）/ Order ID, amount (collected by payment provider)</td>
        <td>计费与开票 / Billing & invoicing</td>
        <td>合同履行 / Performance of contract</td>
    </tr>
    <tr>
        <td>您主动提交 / Voluntarily Provided</td>
        <td>客服沟通、问卷、反馈 / Support tickets, surveys, feedback</td>
        <td>改进服务 / Service improvement</td>
        <td>您的同意 / Your consent</td>
    </tr>
    </tbody>
</table>

<p>
    <span class="zh">我们<strong>不会</strong>超出上述范围收集与提供服务无关的个人信息，也<strong>不会</strong>强制您提供非必要信息。</span>
    <span class="en">We will <strong>NOT</strong> collect personal information beyond the scope above, nor compel you to provide unnecessary information.</span>
</p>

<!-- ===================== 3. 我们如何使用 ===================== -->
<h2>3. 我们如何使用这些信息 <span class="en">How We Use the Information</span></h2>
<ol>
    <li>
        <span class="zh">向您提供、维护、优化本服务的核心功能；</span>
        <span class="en">To provide, maintain, and improve the core features of the Service;</span>
    </li>
    <li>
        <span class="zh">识别与防范欺诈、滥用、攻击等安全风险；</span>
        <span class="en">To detect and prevent fraud, abuse, and security attacks;</span>
    </li>
    <li>
        <span class="zh">履行法律法规要求的义务（如反洗钱、网络安全审计等）；</span>
        <span class="en">To comply with legal obligations (e.g. AML, cybersecurity audits);</span>
    </li>
    <li>
        <span class="zh">在获得您<strong>单独、明确同意</strong>后，用于产品研究、个性化推荐或营销。</span>
        <span class="en">After your <strong>separate and explicit consent</strong>, for product research, personalization, or marketing.</span>
    </li>
</ol>

<!-- ===================== 4. 我们绝不会做的事 ===================== -->
<h2>4. 我们绝不会做的事 <span class="en">What We Will Never Do</span></h2>
<div class="danger">
    <ul>
        <li>
            <span class="zh"><strong>绝不</strong>在未经您授权的情况下，向任何第三方出售、出租、交换您的个人数据；</span>
            <span class="en"><strong>Never</strong> sell, lease, or exchange your personal data with any third party without your authorization;</span>
        </li>
        <li>
            <span class="zh"><strong>绝不</strong>将您的数据用于本政策未明确声明的目的；</span>
            <span class="en"><strong>Never</strong> use your data for purposes not expressly stated in this Policy;</span>
        </li>
        <li>
            <span class="zh"><strong>绝不</strong>读取您在本服务中与他人私下交流的内容，除非法律强制要求或您主动提交给客服处理；</span>
            <span class="en"><strong>Never</strong> read your private communications with others within the Service, unless legally compelled or actively submitted by you to support;</span>
        </li>
        <li>
            <span class="zh"><strong>绝不</strong>以任何形式将未脱敏的用户数据用于 AI 模型训练。</span>
            <span class="en"><strong>Never</strong> use un-anonymized User Data for AI model training in any form.</span>
        </li>
    </ul>
</div>

<!-- ===================== 5. 对外共享 ===================== -->
<h2>5. 何时、如何对外共享 <span class="en">When & How We Share</span></h2>
<p>
    <span class="zh">仅在以下情形下，我们才可能共享您的数据，并在可行时对数据进行<strong>去标识化 / 最小化</strong>处理：</span>
    <span class="en">We will only share your data in the following circumstances, and where feasible, after <strong>de-identification / minimization</strong>:</span>
</p>
<ol>
    <li>
        <span class="zh"><strong>您的明确授权</strong>：您主动授权我们向特定第三方共享；</span>
        <span class="en"><strong>With your explicit consent</strong>: when you actively authorize sharing with a specific third party;</span>
    </li>
    <li>
        <span class="zh"><strong>必要的服务提供商</strong>（如云服务、短信、支付渠道）：仅共享提供服务所必需的最小数据，并通过合同要求其承担保密义务；</span>
        <span class="en"><strong>Necessary service providers</strong> (e.g. cloud, SMS, payment): only the minimum data required, under contractual confidentiality obligations;</span>
    </li>
    <li>
        <span class="zh"><strong>法律要求</strong>：依据有效的法律文书（法院传票、搜查令、监管机构正式要求）进行披露；</span>
        <span class="en"><strong>Legal requirement</strong>: upon a valid legal instrument (e.g. court order, search warrant, official regulatory request);</span>
    </li>
    <li>
        <span class="zh"><strong>重大公共利益</strong>：为保护生命、人身安全或防止重大违法犯罪；</span>
        <span class="en"><strong>Vital public interest</strong>: to protect lives, physical safety, or prevent serious crimes;</span>
    </li>
    <li>
        <span class="zh"><strong>公司合并或资产转让</strong>：在此情形下，我们将要求继受方遵守不低于本政策的保护水平，并提前通知您。</span>
        <span class="en"><strong>Corporate merger or asset transfer</strong>: we will require the successor to apply protections no less than those in this Policy, and notify you in advance.</span>
    </li>
</ol>

<div class="notice">
    <p>
        <span class="zh">对于第 3 项"法律要求"的披露，我们将在法律允许的最大范围内<strong>提前通知您</strong>，并对超出必要范围的要求依法提出异议。</span>
        <span class="en">For disclosures under item (3), we will, to the maximum extent permitted by law, <strong>notify you in advance</strong> and lawfully challenge any request that exceeds what is necessary.</span>
    </p>
</div>

<!-- ===================== 6. 数据安全 ===================== -->
<h2>6. 我们如何保护您的数据 <span class="en">How We Protect Your Data</span></h2>
<ul>
    <li>
        <span class="zh"><strong>传输加密</strong>：全站强制 HTTPS/TLS 1.2+；</span>
        <span class="en"><strong>In-transit encryption</strong>: site-wide HTTPS/TLS 1.2+;</span>
    </li>
    <li>
        <span class="zh"><strong>存储加密</strong>：敏感字段（密码、令牌）使用业界标准算法加密或哈希；</span>
        <span class="en"><strong>At-rest encryption</strong>: sensitive fields (passwords, tokens) encrypted or hashed with industry-standard algorithms;</span>
    </li>
    <li>
        <span class="zh"><strong>访问控制</strong>：最小权限原则、双因素认证、操作审计；</span>
        <span class="en"><strong>Access control</strong>: least-privilege, 2FA, and audit logging;</span>
    </li>
    <li>
        <span class="zh"><strong>备份与容灾</strong>：定期异地加密备份，并定期演练恢复；</span>
        <span class="en"><strong>Backup & DR</strong>: regular off-site encrypted backups with periodic restore drills;</span>
    </li>
    <li>
        <span class="zh"><strong>事件响应</strong>：若发生数据泄露，我们将在法律要求期限内（一般为 72 小时内）通知受影响的用户及监管机构。</span>
        <span class="en"><strong>Incident response</strong>: in case of a data breach, we will notify affected users and regulators within the legally required timeframe (typically 72 hours).</span>
    </li>
</ul>

<!-- ===================== 7. 您的权利 ===================== -->
<h2>7. 您对自己数据享有的权利 <span class="en">Your Rights Over Your Data</span></h2>
<p>
    <span class="zh">您对自己在本服务中的数据享有以下<strong>不可剥夺</strong>的权利：</span>
    <span class="en">You have the following <strong>inalienable</strong> rights over your data in the Service:</span>
</p>
<ol>
    <li>
        <span class="zh"><strong>知情权 / Right to Know</strong>：了解我们如何处理您的数据；</span>
        <span class="en">Know how we process your data;</span>
    </li>
    <li>
        <span class="zh"><strong>访问权 / Right of Access</strong>：查阅、复制您的个人数据；</span>
        <span class="en">Access and obtain a copy of your personal data;</span>
    </li>
    <li>
        <span class="zh"><strong>更正权 / Right to Rectification</strong>：更正不准确或不完整的信息；</span>
        <span class="en">Correct inaccurate or incomplete information;</span>
    </li>
    <li>
        <span class="zh"><strong>删除权 / Right to Erasure</strong>：要求删除您的数据（法律另有规定的除外）；</span>
        <span class="en">Request deletion of your data (except where retention is legally required);</span>
    </li>
    <li>
        <span class="zh"><strong>可携带权 / Right to Data Portability</strong>：以 JSON / CSV / ZIP 等机器可读格式导出您的数据；</span>
        <span class="en">Export your data in a machine-readable format (JSON / CSV / ZIP);</span>
    </li>
    <li>
        <span class="zh"><strong>撤回同意权 / Right to Withdraw Consent</strong>：随时撤回先前提供的同意；</span>
        <span class="en">Withdraw any previously granted consent at any time;</span>
    </li>
    <li>
        <span class="zh"><strong>拒绝自动化决策权 / Right to Object to Automated Decisions</strong>：若存在对您有重大影响的自动化决策，您有权要求人工复核；</span>
        <span class="en">Request human review for automated decisions with material effects on you;</span>
    </li>
    <li>
        <span class="zh"><strong>投诉权 / Right to Complain</strong>：向监管机构投诉。</span>
        <span class="en">Lodge a complaint with the competent authority.</span>
    </li>
</ol>

<div class="highlight">
    <p>
        <span class="zh"><strong>行使方式</strong>：请发送邮件至 <strong>contact@transmtf.com</strong>，并附上足以证明您身份的信息。我们将在 <strong>15 个工作日</strong>内回复（GDPR 场景为 30 日，复杂情形可再延长 60 日并提前告知）。即使您的账号因任何原因被停用，<strong>您依然享有上述权利</strong>，我们将免费配合处理。</span>
        <span class="en"><strong>How to exercise</strong>: email <strong>contact@transmtf.com</strong> with information sufficient to verify your identity. We will respond within <strong>15 business days</strong> (30 days under GDPR, extendable by up to 60 days with notice). Even if your account is suspended for any reason, <strong>you continue to enjoy these rights</strong>, and we will assist free of charge.</span>
    </p>
</div>

<!-- ===================== 8. 数据存储期限 ===================== -->
<h2>8. 数据存储期限 <span class="en">Data Retention</span></h2>
<ul>
    <li>
        <span class="zh">账户存续期间：持续保留；</span>
        <span class="en">While the account is active: retained on an ongoing basis;</span>
    </li>
    <li>
        <span class="zh">账户注销后：用户内容将在 <strong>30 天</strong> 的"冷却期"内可恢复，之后进入删除队列；</span>
        <span class="en">After account deletion: User Content is recoverable during a <strong>30-day cooling-off period</strong>, then enters the deletion queue;</span>
    </li>
    <li>
        <span class="zh">财务、日志、合规类数据：依法保留 <strong>3–10 年</strong>；</span>
        <span class="en">Financial, log, and compliance data: retained for <strong>3–10 years</strong> as required by law;</span>
    </li>
    <li>
        <span class="zh">超出法定期限后，我们将对数据进行匿名化处理或不可逆删除。</span>
        <span class="en">After the statutory retention period, data will be anonymized or irreversibly deleted.</span>
    </li>
</ul>

<!-- ===================== 9. 跨境传输 ===================== -->
<h2>9. 跨境数据传输 <span class="en">Cross-Border Transfers</span></h2>
<p>
    <span class="zh">若涉及跨境传输，我们将遵守《个人信息保护法》《GDPR》等适用法律，采取标准合同条款（SCC）、安全评估或取得您的单独同意等合法机制，并告知境外接收方、目的、方式及您的权利行使方式。</span>
    <span class="en">For any cross-border transfer, we will comply with applicable laws (PIPL, GDPR, etc.) using lawful mechanisms such as Standard Contractual Clauses, security assessments, or obtaining your separate consent, and we will disclose the overseas recipient, purpose, means, and how you may exercise your rights.</span>
</p>

<!-- ===================== 10. 未成年人 ===================== -->
<h2>10. 未成年人保护 <span class="en">Minors</span></h2>
<p>
    <span class="zh">本服务主要面向成年人。若您是未满 <strong>14 周岁</strong> 的未成年人，请在监护人陪同下阅读本政策，并取得监护人同意后再使用本服务。我们会对涉及未成年人的数据采取严格的额外保护措施。</span>
    <span class="en">The Service is intended for adults. If you are under <strong>14 years old</strong>, please read this Policy with a guardian and obtain their consent before using the Service. We apply enhanced safeguards to any data involving minors.</span>
</p>
<!-- ===================== 11. 政策变更 ===================== -->
<h2>11. 政策变更 <span class="en">Changes to this Policy</span></h2>
<p>
    <span class="zh">本政策如有重大变更，我们会通过站内显著位置、邮件或弹窗通知您，并在必要时重新征求您的同意。</span>
    <span class="en">For any material change, we will notify you through prominent in-app notices, email, or pop-ups, and re-obtain your consent where necessary.</span>
</p>

<!-- ===================== 12. 联系我们 ===================== -->
<h2>12. 联系我们 <span class="en">Contact Us</span></h2>
<p>
    <span class="zh">如您对本政策有任何疑问，或希望行使您的数据权利，请通过以下方式联系我们的数据保护负责人：</span>
    <span class="en">For any questions about this Policy or to exercise your data rights, please contact our Data Protection Officer via:</span>
</p>
<ul>
    <li>Email：<strong>contact@transmtf.com</strong></li>
    <li>Security：<strong>contact@transmtf.com</strong></li>
</ul>

</body>
</html>
```
