import asyncio
import io
import json
import os

import aiohttp
import discord
import imagehash
import numpy as np
from discord import Color, Embed
from discord.ext import commands
from dotenv import load_dotenv
from PIL import Image

load_dotenv()

TOKEN = os.getenv("DISCORD_TOKEN")
HASH_FILE = os.getenv("HASH_FILE", "banned_hashes.json")
LOG_CHANNEL_ID = int(os.getenv("LOG_CHANNEL_ID"))
BANNED_ROLE_ID = int(os.getenv("BANNED_ROLE_ID"))
THRESHOLD_8 = os.getenv("THRESHOLD_8", 5)
THRESHOLD_16 = os.getenv("THRESHOLD_16", 12)

# Bot setup
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
bot = commands.Bot(command_prefix="!", intents=intents)

# Globals
BANNED_HASH_ARRAYS = {"phash": {}, "dhash": {}, "whash": {}, "ahash": {}}
session: aiohttp.ClientSession = None


def load_hashes_numpy() -> None:
    global BANNED_HASH_ARRAYS
    if not os.path.exists(HASH_FILE):
        print(f"Error: {HASH_FILE} not found.")
        return

    try:
        with open(HASH_FILE, "r") as f:
            raw_data = json.load(f)

        for h_type in BANNED_HASH_ARRAYS.keys():
            BANNED_HASH_ARRAYS[h_type] = {}
            for h_str in raw_data.get(h_type, []):
                h = imagehash.hex_to_hash(h_str)
                size = h.hash.shape[0]
                arr = np.array(h.hash, dtype=np.uint8).flatten()
                BANNED_HASH_ARRAYS[h_type].setdefault(size, []).append(arr)

        total = sum(len(vs) for ht in BANNED_HASH_ARRAYS.values() for vs in ht.values())
        print(f"Loaded {total} banned hashes")

    except Exception as e:
        print(f"Failed to load hashes: {e}")


def compute_hash_numpy(img: Image.Image, h_type: str, size: int) -> np.ndarray | None:
    """Compute a hash of the given type and size as a flat numpy array"""
    if h_type == "phash":
        h = imagehash.phash(img, hash_size=size)
    elif h_type == "dhash":
        h = imagehash.dhash(img, hash_size=size)
    elif h_type == "whash":
        h = imagehash.whash(img, hash_size=size)
    elif h_type == "ahash":
        h = imagehash.average_hash(img, hash_size=size)
    else:
        return None
    return np.array(h.hash, dtype=np.uint8).flatten()


def detect_image_numpy(image_bytes: bytes) -> dict:
    """Vectorized detection of banned images"""
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    except Exception:
        return {"match": False}

    for h_type, size_dict in BANNED_HASH_ARRAYS.items():
        for size, banned_arrays in size_dict.items():
            current_hash = compute_hash_numpy(img, h_type, size)
            threshold = THRESHOLD_16 if size > 8 else THRESHOLD_8

            for banned_arr in banned_arrays:
                dist = np.sum(current_hash != banned_arr)
                if dist <= threshold:
                    return {"match": True, "type": h_type, "dist": int(dist)}

    return {"match": False}


async def handle_detection(message: discord.Message, result: dict):
    """Delete message, assign role, and log detection"""
    try:
        await message.delete()
        await message.channel.send(
            f"A message from **{message.author.name}** was removed: Suspected Scam Image."
        )
    except discord.Forbidden:
        print("Missing permissions to delete message.")

    role = message.guild.get_role(BANNED_ROLE_ID)
    if role:
        try:
            await message.author.add_roles(role)
        except discord.Forbidden:
            print("Missing permissions to add role.")

    log_channel = bot.get_channel(LOG_CHANNEL_ID)
    if log_channel:
        embed = Embed(
            title="Scam Image Detected",
            color=Color.red(),
            description=f"User: {message.author.mention} ({message.author.id})",
        )
        embed.add_field(name="Action", value="Message Deleted & Quarantined")
        embed.add_field(name="Hash Type", value=result["type"])
        embed.add_field(name="Distance", value=result["dist"])
        await log_channel.send(embed=embed)


@bot.event
async def on_ready():
    print(f"Logged in as {bot.user}")
    global session
    session = aiohttp.ClientSession()
    load_hashes_numpy()


@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        return

    for attachment in message.attachments:
        if attachment.content_type and "image" in attachment.content_type:
            try:
                async with session.get(attachment.url) as res:
                    if res.status == 200:
                        img_data = await res.read()
                        result = detect_image_numpy(img_data)
                        if result.get("match"):
                            await handle_detection(message, result)
                            break
            except Exception as e:
                print(f"Error fetching or processing image: {e}")


@bot.event
async def on_close():
    if session:
        await session.close()


try:
    bot.run(TOKEN)
finally:
    if session:
        asyncio.run(session.close())
