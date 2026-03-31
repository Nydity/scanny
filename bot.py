import discord
from PIL import Image
import imagehash
import io
import aiohttp
import json
import os
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("DISCORD_TOKEN")
HASH_FILE = os.getenv("HASH_FILE", "banned_hashes.json")
LOG_CHANNEL_ID = int(os.getenv("LOG_CHANNEL_ID"))
BANNED_ROLE_ID = int(os.getenv("BANNED_ROLE_ID"))

THRESHOLD_8 = 5
THRESHOLD_16 = 12

intents = discord.Intents.default()
intents.message_content = True
intents.members = True
client = discord.Client(intents=intents)

BANNED_HASH_OBJECTS = {"phash": [], "dhash": [], "whash": [], "ahash": []}


def load_hashes():
    if not os.path.exists(HASH_FILE):
        print(f"Error: {HASH_FILE} not found.")
        return
    try:
        with open(HASH_FILE, "r") as f:
            raw_data = json.load(f)
        for h_type in BANNED_HASH_OBJECTS.keys():
            if h_type in raw_data:
                BANNED_HASH_OBJECTS[h_type] = [
                    imagehash.hex_to_hash(h_str) for h_str in raw_data[h_type]
                ]
        print(f"Loaded hashes. Monitoring for matches...")
    except Exception as e:
        print(f"Failed to load hashes: {e}")


def get_specific_hash(img, h_type, size):
    if h_type == "phash":
        return imagehash.phash(img, hash_size=size)
    if h_type == "dhash":
        return imagehash.dhash(img, hash_size=size)
    if h_type == "whash":
        return imagehash.whash(img, hash_size=size)
    if h_type == "ahash":
        return imagehash.average_hash(img, hash_size=size)
    return None


def detect_image(image_bytes):
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    except Exception:
        return {"match": False}

    computed_cache = {}

    for h_type, banned_list in BANNED_HASH_OBJECTS.items():
        for banned_hash in banned_list:
            size = banned_hash.hash.shape[0]
            cache_key = (h_type, size)
            if cache_key not in computed_cache:
                computed_cache[cache_key] = get_specific_hash(img, h_type, size)

            current_hash = computed_cache[cache_key]
            distance = banned_hash - current_hash
            target_threshold = THRESHOLD_16 if size > 8 else THRESHOLD_8

            if distance <= target_threshold:
                return {"match": True, "type": h_type, "dist": distance}
    return {"match": False}


@client.event
async def on_ready():
    load_hashes()
    print(f"Logged in as {client.user}")


@client.event
async def on_message(message):
    if message.author.bot or not message.guild:
        return

    for attachment in message.attachments:
        if attachment.content_type and "image" in attachment.content_type:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(attachment.url) as resp:
                        if resp.status == 200:
                            img_data = await resp.read()
                            result = detect_image(img_data)

                            if result.get("match"):
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

                                log_channel = client.get_channel(LOG_CHANNEL_ID)
                                if log_channel:
                                    embed = discord.Embed(
                                        title="Scam Image Detected",
                                        color=discord.Color.red(),
                                        description=f"User: {message.author.mention} ({message.author.id})",
                                    )
                                    embed.add_field(
                                        name="Action",
                                        value="Message Deleted & Quarantined",
                                    )
                                    embed.add_field(
                                        name="Hash Type", value=result["type"]
                                    )
                                    embed.add_field(
                                        name="Distance", value=result["dist"]
                                    )
                                    await log_channel.send(embed=embed)

                                break

            except Exception as e:
                print(f"Error: {e}")


client.run(TOKEN)
