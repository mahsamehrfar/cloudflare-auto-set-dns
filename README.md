<div align="center">

<h1>⚡ Cloudflare Auto DNS Set</h1>
<p><b>Smart Clean IP Scanner & Auto DNS Updater built with Xray</b></p>

<img src="https://img.shields.io/badge/Made%20by-MHJ%20Studio-8A2BE2?style=for-the-badge" alt="MHJ Studio">
<img src="https://img.shields.io/badge/Powered%20by-Xray--Core-22B07D?style=for-the-badge" alt="Xray Core">
<img src="https://img.shields.io/badge/Framework-FastAPI-009688?style=for-the-badge" alt="FastAPI">
<img src="https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge" alt="Python Version">
<img width="776" height="893" alt="Screenshot 2026-07-02 221138" src="https://github.com/user-attachments/assets/eb73fe37-8fef-435d-9b7c-7147fbaae79b" />

<br><br>

<a href="#english-version"><b>🇺🇸 English</b></a> •
<a href="#persian-version"><b>🇮🇷 فارسی</b></a>

</div>

---

## 📑 Table of Contents

- 🇺🇸 [English Version](#english-version)
  - [Features](#features)
  - [Prerequisites](#prerequisites)
  - [Installation & Usage](#installation)
  - [Screenshots](#screenshots)
- 🇮🇷 [Persian Version](#persian-version)
- 🤝 [Contributing](#contributing)
- 📄 [License](#license)
- ⚠️ [Disclaimer](#disclaimer)

---

<a id="english-version"></a>
## 🇺🇸 English Version

**Cloudflare Auto DNS Set** is a smart, fully automated tool with designed to scan for clean IPs, test them directly using `Vless`/`Trojan` configs via the Xray core, and automatically update your Cloudflare DNS records.

<a id="features"></a>
### ✨ Features

- 🪄 **Auto-Fetch:** Forget about finding Zone IDs and Record IDs manually. Enter your Cloudflare Token & Domain, and let the system fetch them automatically.
- 💉 **Xray Core Integration:** Real-world tunnel testing using your custom `vless://` or `trojan://` configs to ensure the IP survives strict network filtering.
- ⚡ **3-Stage Smart Scanner:** Socket ping for latency checks, TLS routing check, and live tunnel connection test via Xray.
- 🚀 **Fast-Track:** Instantly test a specific IP and deploy it.
- 💾 **Built-in Database:** Uses a lightweight SQLite DB to safely store your setups, IPs, and configs.

<a id="prerequisites"></a>
### 🛠️ Prerequisites

- Python 3.8 or higher

<a id="installation"></a>
### ⚙️ Installation & Usage

**Step 1: Clone the repository**

```bash
git clone https://github.com/mahsamehrfar/cloudflare-auto-set-dns
cd Cloudflare-Auto-DNS-Set
```

**Step 2: Install requirements**

```bash
install.bat
```

**Step 3: Run the app**

```bash
run.bat
```

Then open your browser and visit: `http://127.0.0.1:8000`

---

<a id="persian-version"></a>
## 🇮🇷 Persian Version

<div align="right">

**Cloudflare Auto DNS Set** یک ابزار قدرتمند و هوشمند با رابط کاربری (UI) فوق‌العاده مدرن و تاریک است که به شما کمک می‌کند بهترین و پایدارترین آی‌پی‌ها (Clean IPs) را اسکن کنید، آن‌ها را با کانفیگ‌های Vless و Trojan توسط هسته Xray تست کنید و در نهایت بهترین آی‌پی را به‌صورت کاملاً اتوماتیک روی رکوردهای DNS کلودفلر خود ثبت کنید.

### ✨ ویژگی‌ها و امکانات

- 🪄 **استخراج جادویی شناسه‌ها:** نیازی به پیدا کردن دستی Zone ID و Record ID نیست؛ فقط دامنه و توکن خود را وارد کنید تا سیستم به‌طور خودکار آن‌ها را پیدا کند.
- 💉 **پشتیبانی از Xray Core:** امکان تزریق کانفیگ‌های `vless://` و `trojan://` جهت تست ترافیک واقعی در شرایط فیلترینگ.
- ⚡ **اسکنر ۳ مرحله‌ای هوشمند:** پینگ سوکت، بررسی مسیر TLS و تست اتصال کانفیگ با هسته Xray.
- 🚀 **تست فوری (Fast-Track):** امکان تست سریع یک آی‌پی خاص و ثبت آن در چند ثانیه.
- 💾 **ذخیره‌سازی هوشمند:** ذخیره تمامی اطلاعات و کانفیگ‌ها در دیتابیس سبک SQLite.

### 🛠️ پیش‌نیازها

- نصب بودن Python نسخه 3.8 به بالا

### ⚙️ نصب و راه‌اندازی

**قدم اول: دریافت سورس کد**

```bash
git clone https://github.com/mahsamehrfar/cloudflare-auto-set-dns
cd Cloudflare-Auto-DNS-Set
```

**قدم دوم: نصب پیش‌نیازها**

```bash
install.bat
```

**قدم سوم: اجرای برنامه**

```bash
run.bat
```

سپس مرورگر خود را باز کرده و آدرس `http://127.0.0.1:8000` را وارد کنید تا پنل کاربری برای شما باز شود.

### 📖 راهنمای استفاده سریع

1. **گرفتن توکن:** در بخش تنظیمات، روی دکمه «گرفتن توکن کلودفلر» کلیک کنید، دسترسی‌ها را تایید کرده و توکن ساخته‌شده را کپی کنید.
2. **استخراج :** دامنه و توکن را وارد کرده و دکمه استخراج خودکار را بزنید تا فرم‌ها پر شوند.
3. **تزریق دیتا:** در تب «دیتا سنتر»، رنج‌های آی‌پی و لینک‌های کانفیگ Vless/Trojan خود را وارد کنید.
4. **شروع عملیات:** در تب داشبورد دکمه «شروع اسکن هوشمند» را بزنید و منتظر بمانید تا بهترین آی‌پی یافت شود. در نهایت روی «تایید نهایی و ثبت» کلیک کنید.

</div>

---

<a id="contributing"></a>
## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](../../issues) if you want to help out.

مشارکت‌ها، گزارش باگ و پیشنهاد قابلیت‌های جدید با کمال میل پذیرفته می‌شود.

<a id="license"></a>
## 📄 License
Apache-2.0 a highly permissive, open-source license

<a id="disclaimer"></a>
## ⚠️ Disclaimer / سلب مسئولیت

This project is intended for educational purposes and network optimization. The user assumes all responsibility for its use.

این پروژه صرفاً جنبه آموزشی و ابزاری برای بهبود کیفیت شبکه دارد و استفاده از آن بر عهده شخص کاربر است.

---

<div align="center">

<img src="https://img.shields.io/badge/Made%20by-MHJ%20Studio-8A2BE2?style=for-the-badge" alt="MHJ Studio">

⭐ **If you find this project useful, consider giving it a star!**

</div>
