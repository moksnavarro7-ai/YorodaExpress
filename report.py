import asyncio
import os
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, ConversationHandler, filters
from telethon import TelegramClient
from telethon.tl.types import (
    InputReportReasonSpam,
    InputReportReasonFake,
    InputReportReasonViolence,
    InputReportReasonPornography,
    InputReportReasonOther,
)

# ============================================
# DIRECT VARIABLES (No environment variables)
# ============================================
API_ID = 35383294  # Direct integer, no int() needed
API_HASH = "685a6c1691a92cdd05ab66f5c3f5161b"
PHONE = "+639456655624"
BOT_TOKEN = "8824864653:AAEmpXwgdiGLKqLq_VjiIcuvRbfFvcNbDHY"

# ============================================
# REASON MAP
# ============================================
reason_map = {
    "spam": InputReportReasonSpam(),
    "fake": InputReportReasonFake(),
    "violence": InputReportReasonViolence(),
    "porn": InputReportReasonPornography(),
    "other": InputReportReasonOther()
}

# ============================================
# CONVERSATION STATES
# ============================================
USERNAME, REASON, COUNT = range(3)

# ============================================
# COMMAND HANDLERS
# ============================================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("📌 *YORODA REPORT BOT*\n\nSend the target username (without @):")
    return USERNAME

async def username_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data['username'] = update.message.text.strip().replace("@", "")
    await update.message.reply_text("📌 *Select report reason:*\n\nspam - Spam messages\nfake - Fake account\nviolence - Violence content\nporn - Pornography\nother - Other reasons")
    return REASON

async def reason_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    reason = update.message.text.strip().lower()
    if reason not in reason_map:
        await update.message.reply_text("❌ Invalid reason! Choose: spam, fake, violence, porn, other")
        return REASON
    context.user_data['reason'] = reason
    await update.message.reply_text("📌 *How many recent messages to report?*\n(Example: 50)")
    return COUNT

async def count_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        count = int(update.message.text.strip())
    except ValueError:
        await update.message.reply_text("❌ Please enter a valid number!")
        return COUNT

    username = context.user_data['username']
    reason = context.user_data['reason']

    await update.message.reply_text("⏳ Starting report process...")

    client = TelegramClient("session", API_ID, API_HASH)
    try:
        await client.start(phone=PHONE)
    except Exception as e:
        await update.message.reply_text(f"❌ Connection error: {e}")
        return ConversationHandler.END

    try:
        entity = await client.get_entity(username)
        messages = await client.get_messages(entity, limit=count)
        success = 0
        for i, msg in enumerate(messages, 1):
            try:
                await client.report_messages(entity, [msg.id], reason_map[reason], "Reported via Yoroda Bot")
                success += 1
                await asyncio.sleep(1)  # Prevent rate limiting
            except Exception as e:
                await update.message.reply_text(f"Error on message {i}: {e}")
        await update.message.reply_text(f"✅ *Complete!*\nSuccess: {success}/{count}")
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")
    finally:
        await client.disconnect()

    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("❌ Cancelled.")
    return ConversationHandler.END

# ============================================
# MAIN FUNCTION
# ============================================
def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    conv = ConversationHandler(
        entry_points=[CommandHandler("start", start)],
        states={
            USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, username_handler)],
            REASON: [MessageHandler(filters.TEXT & ~filters.COMMAND, reason_handler)],
            COUNT: [MessageHandler(filters.TEXT & ~filters.COMMAND, count_handler)],
        },
        fallbacks=[CommandHandler("cancel", cancel)]
    )

    app.add_handler(conv)
    print("🏳️ Yoroda Report Bot is running...")
    app.run_polling()

if __name__ == "__main__":
    main()
