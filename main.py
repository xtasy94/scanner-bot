import discord
from discord.ext import commands
import requests
import tempfile
import os
import time
from dotenv import load_dotenv
load_dotenv()

BOT_TOKEN = os.getenv('BOT_TOKEN')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
METADEFENDER_API_KEY = os.getenv('METADEFENDER_API_KEY')

if not all([BOT_TOKEN, VIRUSTOTAL_API_KEY, METADEFENDER_API_KEY]):
    raise EnvironmentError("Missing required environment variables. Please set BOT_TOKEN, VIRUSTOTAL_API_KEY, and METADEFENDER_API_KEY.")

intents = discord.Intents.default()
intents.message_content = True  # enable msg content intent from discord dev portal

default_prefix = "!"
bot = commands.Bot(command_prefix=default_prefix, intents=intents)

guild_prefixes = {}

@bot.event
async def on_ready():
    print(f'Logged in as {bot.user}!')
    await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.listening, name="!bothelp"))

@bot.event
async def on_guild_join(guild):
    guild_prefixes[guild.id] = default_prefix

def get_prefix(bot, message):
    return guild_prefixes.get(message.guild.id, default_prefix)

bot.command_prefix = get_prefix

@bot.command()
@commands.has_permissions(manage_guild=True)
async def setprefix(ctx, prefix: str):
    guild_prefixes[ctx.guild.id] = prefix
    embed = discord.Embed(title="Prefix Changed", description=f"Prefix set to `{prefix}`", color=discord.Color.green())
    await ctx.send(embed=embed)

@setprefix.error
async def setprefix_error(ctx, error):
    if isinstance(error, commands.MissingPermissions):
        embed = discord.Embed(title="Permission Denied", description="You do not have permission to change the prefix. You need the Manage Server permission.", color=discord.Color.red())
        await ctx.send(embed=embed)

@bot.command(name="bothelp")
async def bothelp(ctx):
    prefix = guild_prefixes.get(ctx.guild.id, default_prefix)
    help_message = (
        f"**Scanner Bot Commands**\n"
        f"Use the commands with the prefix: `{prefix}`\n\n"
        f"**VirusTotal Commands**\n"
        f"`{prefix}scanurl <url>` - Scans a given URL using VirusTotal.\n"
        f"`{prefix}scanfile <file_attachment>` - Scans an uploaded file using VirusTotal.\n"
        f"`{prefix}hashlookup <md5/sha256>` - Looks up a hash using VirusTotal.\n\n"
        f"**Metadefender Commands**\n"
        f"`{prefix}mdscanurl <url>` - Scans a given URL using Metadefender.\n"
        f"`{prefix}mdscanfile <file_attachment>` - Scans an uploaded file using Metadefender.\n"
        f"`{prefix}mdhashlookup <md5/sha256>` - Looks up a hash using Metadefender.\n\n"
        f"**Set Prefix**\n"
        f"`{prefix}setprefix <new_prefix>` - Changes the command prefix (requires Manage Server permission).\n"
    )
    embed = discord.Embed(title="Help Message", description=help_message, color=discord.Color.blue())
    await ctx.send(embed=embed)

@bot.command()
async def scanurl(ctx, *, url: str):
    embed = discord.Embed(title="VirusTotal URL Scan", description="Scanning the URL...", color=discord.Color.orange())
    message = await ctx.send(embed=embed)

    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    params = {'url': url}
    response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, params=params)
    if response.status_code == 200:
        scan_id = response.json().get('data', {}).get('id')
        report_url = f'https://www.virustotal.com/api/v3/analyses/{scan_id}'
        time.sleep(10)  # Wait a bit longer for the scan to complete
        report_response = requests.get(report_url, headers=headers)
        if report_response.status_code == 200:
            report = report_response.json()
            stats = report.get('data', {}).get('attributes', {}).get('stats', {})
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            
            url_id = report.get('meta', {}).get('url_info', {}).get('id')
            url_info_response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}', headers=headers)
            community_score = "N/A"
            if url_info_response.status_code == 200:
                url_info = url_info_response.json()
                community_score = url_info.get('data', {}).get('attributes', {}).get('reputation', 'N/A')
            
            if malicious == 0:
                result = "URL is clean"
                color = discord.Color.green()
            else:
                result = f"URL detected as malicious by {malicious} out of {total} scanners"
                color = discord.Color.red()
            
            embed = discord.Embed(title="VirusTotal URL Scan Result", color=color)
            embed.add_field(name="Scan Result", value=result, inline=False)
            embed.add_field(name="Community Score", value=str(community_score), inline=False)
            embed.add_field(name="Scanned URL", value=url, inline=False)
            await message.edit(embed=embed)
        else:
            embed = discord.Embed(title="Error", description="Failed to retrieve scan report.", color=discord.Color.red())
            await message.edit(embed=embed)
    else:
        embed = discord.Embed(title="Error", description="Failed to scan URL.", color=discord.Color.red())
        await message.edit(embed=embed)

@bot.command()
async def scanfile(ctx, file: discord.Attachment):
    embed = discord.Embed(title="VirusTotal File Scan", description="Downloading and scanning the file...", color=discord.Color.orange())
    message = await ctx.send(embed=embed)

    with tempfile.TemporaryDirectory() as temp_dir:
        file_path = os.path.join(temp_dir, file.filename)
        await file.save(file_path)

        with open(file_path, 'rb') as f:
            files = {'file': (file.filename, f)}
            headers = {'x-apikey': VIRUSTOTAL_API_KEY}
            response = requests.post('https://www.virustotal.com/api/v3/files', files=files, headers=headers)
            if response.status_code == 200:
                scan_id = response.json().get('data', {}).get('id')
                report_url = f'https://www.virustotal.com/api/v3/analyses/{scan_id}'
                time.sleep(10)  # Wait a few seconds for the scan to complete
                report_response = requests.get(report_url, headers=headers)
                if report_response.status_code == 200:
                    report = report_response.json()
                    scan_results = report.get('data', {}).get('attributes', {}).get('status', 'Unknown')
                    result = f"File scan status: {scan_results}."
                    embed = discord.Embed(title="VirusTotal File Scan Result", description=result, color=discord.Color.green() if scan_results == 'completed' else discord.Color.red())
                    await message.edit(embed=embed)
                else:
                    embed = discord.Embed(title="Error", description="Failed to retrieve scan results.", color=discord.Color.red())
                    await message.edit(embed=embed)
            else:
                embed = discord.Embed(title="Error", description="Failed to scan file.", color=discord.Color.red())
                await message.edit(embed=embed)

@bot.command()
async def hashlookup(ctx, *, hash_value: str):
    embed = discord.Embed(title="VirusTotal Hash Lookup", description="Looking up the hash...", color=discord.Color.orange())
    message = await ctx.send(embed=embed)

    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    response = requests.get(f'https://www.virustotal.com/api/v3/files/{hash_value}', headers=headers)
    if response.status_code == 200:
        report = response.json()
        scan_results = report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        if scan_results:
            malicious = scan_results.get('malicious', 0)
            total = sum(scan_results.values())
            community_score = report.get('data', {}).get('attributes', {}).get('reputation', 'N/A')
            
            if malicious == 0:
                result = "File is clean"
                color = discord.Color.green()
            else:
                result = f"File detected as malicious by {malicious} out of {total} scanners"
                color = discord.Color.red()
            
            embed = discord.Embed(title="VirusTotal Hash Lookup Result", color=color)
            embed.add_field(name="Scan Result", value=result, inline=False)
            embed.add_field(name="Community Score", value=str(community_score), inline=False)
            embed.add_field(name="Hash", value=hash_value, inline=False)
            await message.edit(embed=embed)
        else:
            embed = discord.Embed(title="Error", description="Failed to retrieve scan results.", color=discord.Color.red())
            await message.edit(embed=embed)
    else:
        embed = discord.Embed(title="Error", description="Failed to lookup hash.", color=discord.Color.red())
        await message.edit(embed=embed)

import time

@bot.command()
async def mdscanurl(ctx, *, url: str):
    embed = discord.Embed(title="Metadefender URL Scan", description="Scanning the URL...", color=discord.Color.orange())
    message = await ctx.send(embed=embed)

    headers = {
        'apikey': METADEFENDER_API_KEY,
        'content-type': 'application/json'
    }
    data = {'url': url}
    response = requests.post('https://api.metadefender.com/v4/url', headers=headers, json=data)
    if response.status_code == 200:
        scan_id = response.json().get('data_id')
        report_url = f'https://api.metadefender.com/v4/url/{scan_id}'
        
        # Poll for results
        for _ in range(30):  # Try for up to 30 seconds
            time.sleep(1)
            report_response = requests.get(report_url, headers=headers)
            if report_response.status_code == 200:
                report = report_response.json()
                scan_result = report.get('scan_results', {})
                if scan_result.get('scan_all_result_a') != 'In Progress':
                    break
        else:
            embed = discord.Embed(title="Error", description="Scan timed out. Please try again later.", color=discord.Color.red())
            await message.edit(embed=embed)
            return

        if report_response.status_code == 200:
            scan_result = report.get('scan_results', {})
            total_avs = scan_result.get('total_detected_avs', 0)
            total_engines = scan_result.get('total_avs', 0)
            overall_result = scan_result.get('scan_all_result_a', 'Unknown')

            if overall_result == 'No Threat Detected':
                result = "URL is clean"
                color = discord.Color.green()
            else:
                result = f"URL detected as malicious by {total_avs} out of {total_engines} scanners"
                color = discord.Color.red()

            embed = discord.Embed(title="Metadefender URL Scan Result", color=color)
            embed.add_field(name="Scan Result", value=result, inline=False)
            embed.add_field(name="Overall Result", value=overall_result, inline=False)
            embed.add_field(name="Scanned URL", value=url, inline=False)
            await message.edit(embed=embed)
        else:
            embed = discord.Embed(title="Error", description="Failed to retrieve scan report.", color=discord.Color.red())
            await message.edit(embed=embed)
    else:
        embed = discord.Embed(title="Error", description="Failed to scan URL.", color=discord.Color.red())
        await message.edit(embed=embed)

@bot.command()
async def mdscanfile(ctx, file: discord.Attachment):
    embed = discord.Embed(title="Metadefender File Scan", description="Downloading and scanning the file...", color=discord.Color.orange())
    message = await ctx.send(embed=embed)

    with tempfile.TemporaryDirectory() as temp_dir:
        file_path = os.path.join(temp_dir, file.filename)
        await file.save(file_path)

        with open(file_path, 'rb') as f:
            files = {'file': (file.filename, f)}
            headers = {'apikey': METADEFENDER_API_KEY}
            response = requests.post('https://api.metadefender.com/v4/file', files=files, headers=headers)
            if response.status_code == 200:
                scan_id = response.json().get('data_id')
                report_url = f'https://api.metadefender.com/v4/file/{scan_id}'
                
                # Poll for results
                for _ in range(60):  # Try for up to 60 seconds
                    time.sleep(1)
                    report_response = requests.get(report_url, headers=headers)
                    if report_response.status_code == 200:
                        report = report_response.json()
                        scan_result = report.get('scan_results', {})
                        if scan_result.get('scan_all_result_a') != 'In Progress':
                            break
                else:
                    embed = discord.Embed(title="Error", description="Scan timed out. Please try again later.", color=discord.Color.red())
                    await message.edit(embed=embed)
                    return

                if report_response.status_code == 200:
                    scan_result = report.get('scan_results', {})
                    total_avs = scan_result.get('total_detected_avs', 0)
                    total_engines = scan_result.get('total_avs', 0)
                    overall_result = scan_result.get('scan_all_result_a', 'Unknown')

                    if overall_result == 'No Threat Detected':
                        result = "File is clean"
                        color = discord.Color.green()
                    else:
                        result = f"File detected as malicious by {total_avs} out of {total_engines} scanners"
                        color = discord.Color.red()

                    embed = discord.Embed(title="Metadefender File Scan Result", color=color)
                    embed.add_field(name="Scan Result", value=result, inline=False)
                    embed.add_field(name="Overall Result", value=overall_result, inline=False)
                    embed.add_field(name="Scanned File", value=file.filename, inline=False)
                    await message.edit(embed=embed)
                else:
                    embed = discord.Embed(title="Error", description="Failed to retrieve scan report.", color=discord.Color.red())
                    await message.edit(embed=embed)
            else:
                embed = discord.Embed(title="Error", description="Failed to scan file.", color=discord.Color.red())
                await message.edit(embed=embed)

@bot.command()
async def mdhashlookup(ctx, *, hash_value: str):
    embed = discord.Embed(title="Metadefender Hash Lookup", description="Looking up the hash...", color=discord.Color.orange())
    message = await ctx.send(embed=embed)

    headers = {
        'apikey': METADEFENDER_API_KEY
    }
    response = requests.get(f'https://api.metadefender.com/v4/hash/{hash_value}', headers=headers)
    if response.status_code == 200:
        report = response.json()
        scan_results = report.get('scan_results', {})
        if scan_results:
            total_avs = scan_results.get('total_avs', 0)
            total_detected = scan_results.get('total_detected_avs', 0)
            overall_result = scan_results.get('scan_all_result_a', 'Unknown')

            if overall_result == 'No Threat Detected':
                result = "File is clean"
                color = discord.Color.green()
            else:
                result = f"File detected as malicious by {total_detected} out of {total_avs} scanners"
                color = discord.Color.red()

            file_info = report.get('file_info', {})
            file_size = file_info.get('file_size', 'Unknown')
            file_type = file_info.get('file_type', 'Unknown')

            embed = discord.Embed(title="Metadefender Hash Lookup Result", color=color)
            embed.add_field(name="Scan Result", value=result, inline=False)
            embed.add_field(name="Overall Result", value=overall_result, inline=False)
            embed.add_field(name="File Size", value=f"{file_size} bytes", inline=True)
            embed.add_field(name="File Type", value=file_type, inline=True)
            embed.add_field(name="Hash", value=hash_value, inline=False)
            await message.edit(embed=embed)
        else:
            embed = discord.Embed(title="Error", description="Failed to retrieve scan results.", color=discord.Color.red())
            await message.edit(embed=embed)
    else:
        embed = discord.Embed(title="Error", description="Failed to lookup hash.", color=discord.Color.red())
        await message.edit(embed=embed)

if __name__ == "__main__":
    bot.run(BOT_TOKEN)