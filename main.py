import os
import logging
import tempfile
import re
from pathlib import Path
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# CONFIG - Lit le token sur Railway. Ne mets rien ici.
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") 
AUTHORIZED_USERS = [] # Laisse [] pour tout le monde. Ou mets [123456] pour bloquer

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Sécurité: Crash si pas de token sur Railway
if not TOKEN:
    logger.critical("❌ ERREUR FATALE: Variable TELEGRAM_BOT_TOKEN manquante sur Railway")
    exit(1)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🤖 Bot VPN Analyzer V2 prêt.\n\n"
        "Envoie-moi un fichier.ovpn ou.conf\n"
        "Je sors: User, Pass, Host:Port"
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🔍 Analyse de fichiers VPN\n"
        "J'extrais:\n"
        "1. Credentials: username, password, auth-user-pass\n"
        "2. Endpoints: remote host:port\n"
        "Usage: Envoie juste le fichier."
    )

async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Vérif accès
    if AUTHORIZED_USERS and update.effective_user.id not in AUTHORIZED_USERS:
        return await update.message.reply_text("⛔ Non autorisé.")

    file = update.message.document
    if not file.file_name.lower().endswith(('.ovpn', '.conf', '.txt')):
        return await update.message.reply_text("❌ Extension non supportée. Envoie.ovpn ou.conf")

    msg = await update.message.reply_text(f"📥 Analyse de {file.file_name}...")
    file_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(file.file_name).suffix) as tmp:
            file_path = tmp.name
            await file.download_to_drive(file_path)
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Extraction Credentials
        creds = re.findall(r'(?:username|auth-user-pass|password|user|pass)\s*[:=]\s*([^\s\r\n]+)', content, re.I)
        creds = list(set([c.strip('"') for c in creds if len(c) > 2]))
        creds_text = "\n".join([f" • {c}" for c in creds]) if creds else " ℹ️ Aucun trouvé"
        
        # Extraction Endpoints
        eps = re.findall(r'(?:remote|Endpoint)\s+([\d\.a-zA-Z\-]+)\s+(\d+)', content, re.I)
        eps = list(set(eps))
        eps_text = "\n".join([f" • {h}:{p}" for h,p in eps]) if eps else " ℹ️ Aucun trouvé"

        result = f"📄 **{file.file_name}**\n\n🔑 **Credentials:**\n{creds_text}\n\n🌐 **Endpoints:**\n{eps_text}"
        
        await msg.edit_text(result)

    except Exception as e:
        await msg.edit_text(f"❌ Erreur: {e}")
        logger.error(f"Error processing file: {e}")
    finally:
        if file_path and os.path.exists(file_path): os.unlink(file_path)

def main():
    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    logger.info("🚀 Bot démarré et en écoute...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
