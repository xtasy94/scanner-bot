## Scanner Bot

![Python](https://img.shields.io/badge/python-3.7%2B-blue)
![Discord.py](https://img.shields.io/badge/discord.py-1.7.3-blue)
![License](https://img.shields.io/badge/license-CC%20BY--NC--ND-brightgreen)
![Contributions](https://img.shields.io/badge/contributions-welcome-brightgreen)

Scanner Bot is a Discord bot designed to enhance security by scanning URLs, files, and hashes using VirusTotal and Metadefender APIs, providing valuable security insights.

### Features

- **URL scanning**: Analyze the safety of URLs in real-time.
- **File scanning**: Scan attached files for potential threats.
- **Hash lookup**: Check file hashes against known databases.
- **Integration with VirusTotal and Metadefender APIs**: Utilize robust security APIs for comprehensive threat analysis.
- **Customizable command prefix**: Tailor commands to suit your server's needs.

### Prerequisites

Ensure you have the following installed:

- ![Python](https://img.shields.io/badge/python-3.7%2B-blue)
- ![Discord.py](https://img.shields.io/badge/discord.py-1.7.3-blue)
- ![Requests](https://img.shields.io/badge/requests-2.25.1-orange)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/xtasy94/scanner-bot.git
   cd scanner-bot
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables:**
   Create a `.env` file in the root directory with:
   ```env
   BOT_TOKEN=your_discord_bot_token
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   METADEFENDER_API_KEY=your_metadefender_api_key
   ```
   Replace placeholders with your actual API keys and bot token.

### Usage

Start the bot:
```bash
python main.py
```

#### Commands

- `!scanurl <url>`: Scan a URL using VirusTotal.
- `!scanfile <attachment>`: Scan an attached file using VirusTotal.
- `!hashlookup <hash>`: Look up a file hash using VirusTotal.
- `!mdscanurl <url>`: Scan a URL using Metadefender.
- `!mdscanfile <attachment>`: Scan an attached file using Metadefender.
- `!mdhashlookup <hash>`: Look up a file hash using Metadefender.
- `!setprefix <new_prefix>`: Customize the command prefix.
- `!bothelp`: Display help information.

### Contributing

![Contributions](https://img.shields.io/badge/contributions-welcome-brightgreen)

Contributions via Pull Requests are welcomed and encouraged!

### License

![License](https://img.shields.io/badge/license-CC%20BY--NC--ND-brightgreen)

This project is licensed under the [CC BY-NC-ND License](LICENSE).

### Disclaimer

This bot is intended for educational and informational purposes only. Exercise caution when interacting with potentially harmful content.

### Acknowledgements

- [Discord.py](https://discordpy.readthedocs.io/)
- [VirusTotal API](https://developers.virustotal.com/reference)
- [Metadefender API](https://www.opswat.com/developers/metadefender)
