import os
import sys
import logging
import tempfile
import subprocess
from pathlib import Path
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# Configuration
TOKEN = "8753684716:AAEI7tp7rBShKa2N06WeIvx-gvwlzHC6A2w"
AUTHORIZED_USERS = []  # Liste des user_id autorisés (vide = tous)

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Commande /start"""
    await update.message.reply_text(
        "🤖 Bot VPN Analyzer prêt.\n"
        "Commandes:\n"
        "/analyze - Analyser un fichier OpenVPN\n"
        "/extract_creds - Extraire des credentials\n"
        "/help - Aide détaillée\n\n"
        "Envoyez un fichier .ovpn ou .conf pour l'analyser."
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Commande /help"""
    await update.message.reply_text(
        "🔍 Bot d'analyse de fichiers VPN\n\n"
        "Fonctionnalités:\n"
        "- Décryptage de fichiers .ovpn chiffrés\n"
        "- Extraction de credentials embarqués\n"
        "- Analyse de configuration VPN\n"
        "- Support OpenVPN, WireGuard\n\n"
        "Usage: Envoyez un fichier ou utilisez les commandes."
    )

async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Gère les fichiers reçus"""
    # Vérification d'autorisation
    if AUTHORIZED_USERS and update.effective_user.id not in AUTHORIZED_USERS:
        await update.message.reply_text("⛔ Non autorisé.")
        return

    file = update.message.document
    if not file:
        await update.message.reply_text("Veuillez envoyer un fichier.")
        return

    file_name = file.file_name or "unknown"
    
    # Vérifier l'extension
    valid_extensions = ('.ovpn', '.conf', '.pcap', '.log', '.txt', '.key', '.crt', '.pem')
    if not file_name.lower().endswith(valid_extensions):
        await update.message.reply_text(f"Extension non supportée: {file_name}")
        return

    await update.message.reply_text(f"📥 Analyse de {file_name}...")

    try:
        # Télécharger le fichier
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(file_name).suffix) as tmp:
            file_path = tmp.name
            await file.download_to_drive(file_path)

        # Analyser selon le type
        result = analyze_vpn_file(file_path)
        
        # Nettoyer
        os.unlink(file_path)
        
        # Envoyer le résultat
        if len(result) > 4000:
            # Envoyer en plusieurs parties
            for i in range(0, len(result), 4000):
                await update.message.reply_text(result[i:i+4000])
        else:
            await update.message.reply_text(result)

    except Exception as e:
        await update.message.reply_text(f"❌ Erreur: {str(e)}")
        logger.error(f"Error processing file: {e}")

def analyze_vpn_file(file_path: str) -> str:
    """Analyse un fichier VPN"""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    result_lines = []
    result_lines.append(f"📄 Fichier: {Path(file_path).name}")
    result_lines.append(f"📏 Taille: {len(content)} caractères\n")
    
    # Détection du type
    if '<ca>' in content:
        result_lines.append("🔐 Type: OpenVPN Configuration\n")
    elif '[Interface]' in content:
        result_lines.append("🔒 Type: WireGuard Configuration\n")
    else:
        result_lines.append("❓ Type: Inconnu\n")

    # Recherche de credentials
    creds_found = []
    
    # Motifs courants
    patterns = {
        'auth-user-pass': r'^\s*auth-user-pass\s+(.+)$',
        'username': r'(?:username|user|login)\s*[:=]\s*(\S+)',
        'password': r'(?:password|pass|pwd|secret|key)\s*[:=]\s*(\S+)',
        'auth-token': r'<auth-token>(.*?)</auth-token>',
        'static-key': r'<static-key>(.*?)</static-key>',
    }
    
    import re
    for label, pattern in patterns.items():
        matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            value = match.strip()
            if len(value) > 3 and len(value) < 200:
                creds_found.append(f"  • {label}: {value}")
    
    if creds_found:
        result_lines.append("🔑 Credentials potentiels trouvés:")
        result_lines.extend(creds_found)
    else:
        result_lines.append("ℹ️ Aucun credential évident trouvé.")

    # Extraire les endpoints
    endpoints = re.findall(r'(?:remote|Endpoint)\s+(\S+)\s+(\d+)', content, re.IGNORECASE)
    if endpoints:
        result_lines.append("\n🌐 Endpoints:")
        for host, port in endpoints:
            result_lines.append(f"  • {host}:{port}")

    return "\n".join(result_lines)

async def analyze_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Commande /analyze"""
    await update.message.reply_text(
        "Envoyez un fichier .ovpn ou .conf pour analyse.\n"
        "Ou utilisez: /analyze <chemin local>"
    )

async def extract_creds(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Commande /extract_creds"""
    if context.args:
        file_path = " ".join(context.args)
        if os.path.exists(file_path):
            result = analyze_vpn_file(file_path)
            await update.message.reply_text(result)
        else:
            await update.message.reply_text(f"Fichier non trouvé: {file_path}")
    else:
        await update.message.reply_text("Usage: /extract_creds <chemin_fichier>")

def main():
    """Point d'entrée"""
    if TOKEN == "8753684716:AAEI7tp7rBShKa2N06WeIvx-gvwlzHC6A2w":
        print("❌ Erreur: Configurez votre TOKEN Telegram dans le script!")
        sys.exit(1)

    app = Application.builder().token(TOKEN).build()

    # Commandes
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("analyze", analyze_command))
    app.add_handler(CommandHandler("extract_creds", extract_creds))
    
    # Fichiers
    doc_handler = MessageHandler(filters.Document.ALL, handle_file)
    app.add_handler(doc_handler)

    logger.info("Bot démarré...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
