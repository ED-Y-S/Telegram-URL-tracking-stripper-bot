import os
import re
import logging
import sqlite3
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
import requests
from typing import Optional, Tuple

from telegram import Update, Chat, Message
from telegram.constants import ParseMode
from telegram.ext import ApplicationBuilder, ContextTypes, CommandHandler, MessageHandler, filters

from database import Database

from telegram import __version__ as TG_VER

try:
    from telegram import __version_info__
except ImportError:
    __version_info__ = (0, 0, 0, 0, 0)  # type: ignore[assignment]

if __version_info__ < (20, 0, 0, "alpha", 1):
    raise RuntimeError(
        f"This example is not compatible with your current PTB version {TG_VER}. To view the "
        f"{TG_VER} version of this example, "
        f"visit https://docs.python-telegram-bot.org/en/v{TG_VER}/examples.html"
    )

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.DEBUG
)

URL_REGEX_PATTEN = re.compile(
    r"https?://(?:www\.)?[-a-zA-Z\d@:%._\+~#=]{1,256}\.[a-zA-Z\d()]{1,6}\b(?:[-a-zA-Z\d)@:%_\+.~#?&/=]*)"
)

from rule import read_adguard_rules

rulelist = read_adguard_rules()


def strip_url(url: str):
    return rulelist.strip_url(url)
    # parser = urlparse(url)
    # hostname = parser.hostname
    # query = parse_qs(parser.query)
    #
    # is_modified = False
    # if hostname.endswith('music.163.com'):
    #     for q in ['uct', 'dlt', 'app_version', 'sc', 'tn']:
    #         if q in query:
    #             query.pop(q)
    #             is_modified = True
    # elif hostname.endswith('b23.tv'):
    #     r = requests.get(url)  # follow 302
    #     return strip_url(r.url)
    # elif hostname.endswith('bilibili.com'):
    #     query.clear()
    #     is_modified = True
    # elif hostname.endswith('twitter.com'):
    #     query.clear()
    #     is_modified = True
    #
    # if is_modified:
    #     parser = parser._replace(query=urlencode(query, doseq=True))
    #     url_stripped = urlunparse(parser)
    #     return True, url_stripped
    # else:
    #     return False, url


def strip_text(msg: Message) -> Tuple[bool, Optional[str]]:
    logging.debug(f'stripping {msg.text}')
    split_list = []
    pre = 0
    is_modified = False
    for match in URL_REGEX_PATTEN.finditer(msg.text):
        if pre < match.start():
            split_list.append(msg.text[pre:match.start()])
        is_stripped, url_stripped = strip_url(match.group())
        if is_stripped:
            is_modified = True
            split_list.append(url_stripped)
        else:
            split_list.append(match.group())
        pre = match.end()
    if pre < len(msg.text):
        split_list.append(msg.text[pre:])
    if is_modified:
        result = ''.join(split_list)
        return True, result
    else:
        return False, None


def strip_markdown(msg: Message):
    raise NotImplementedError


async def meow(update: Update, context):
    chat = update.effective_chat
    log_prefix = f'{chat.type} @{chat.username}[{chat.id}]'
    logging.info(f'{log_prefix}: got /meow')
    await update.effective_message.reply_text("喵～")


async def start(update: Update, context):
    chat = update.effective_chat
    log_prefix = f'{chat.type} @{chat.username}[{chat.id}]'
    logging.info(f'{log_prefix}: got /start')
    if chat.type in [Chat.PRIVATE, chat.GROUP, chat.SUPERGROUP]:
        await chat.send_message(
            "这个 Bot 可以自动移除消息中的 URL 跟踪参数，帮助保护隐私，"
            "可以加入群组中（需要给「Delete Message」管理员权限，并发送 `/enable` 启用），"
            "或者频道中（需要「Edit Message of Others」管理员权限）。"
            "\n\n"
            "This bot can automatically remove URL tracking parameters in messages to protect privacy, "
            "You can add it to a group \(\"Delete Message\" admin right is necessary, and sending `/enable` to enable it\), "
            "or add it to a channel \(\"Edit Message of Others\" admin right is necessary\)\.",
            parse_mode=ParseMode.MARKDOWN_V2
        )


async def enable(update: Update, context):
    chat = update.effective_chat
    log_prefix = f'{chat.type} @{chat.username}[{chat.id}]'
    if chat.type in [Chat.GROUP, Chat.SUPERGROUP]:
        logging.info(f'{log_prefix}: got /enable')
        await update.effective_message.reply_text("Enabled!")
        db.add_if_not_contains(chat.id)
        logging.info(f'{log_prefix}: enabled')
    else:
        logging.info(f'{log_prefix}: got /enable')
        await update.effective_message.reply_text("Bot can only be enabled in a group!")
        logging.info(f'{log_prefix}: dismissed')


async def disable(update: Update, context):
    chat = update.effective_chat
    log_prefix = f'{chat.type} @{chat.username}[{chat.id}]'
    if chat.type in [Chat.GROUP, Chat.SUPERGROUP]:
        logging.info(f'{log_prefix}: got /disable')
        await update.effective_message.reply_text("Disabled!")
        db.delete(chat.id)
        logging.info(f'{log_prefix}: disabled')
    else:
        logging.info(f'{log_prefix}: got /disable')
        await update.effective_message.reply_text("Bot can only be disabled in a group!")
        logging.info(f'{log_prefix}: dismissed')


async def settings(update: Update, context):
    chat = update.effective_chat
    log_prefix = f'{chat.type} @{chat.username}[{chat.id}]'
    logging.info(f'{log_prefix}: got /settings')
    await update.effective_message.reply_text("Settings")


# parse = re.sub(r"([_*\[\]()~`>\#\+\-=|\.!])", r"\\\1", text)
# reparse = re.sub(r"\\\\([_*\[\]()~`>\#\+\-=|\.!])", r"\1", parse)

async def msg_handler(update: Update, context):
    chat = update.effective_chat
    log_prefix = f'{chat.type} @{chat.username}[{chat.id}]'

    if chat.type in [Chat.GROUP, Chat.SUPERGROUP]:

        # 在已经启用的群组，并且忽略关联频道自动转发到群组的消息
        if db.contains(chat.id) and not update.effective_message.is_automatic_forward:

            logging.info(f'{log_prefix}: got message')
            is_modified, result = strip_text(update.effective_message)
            if is_modified:
                logging.info(f'{log_prefix}: message stripped')
                if update.effective_user.username is not None:
                    reply_text = f'''
@{update.effective_user.username}
Your URL contains tracking parameters and has been deleted and modified:
    
{result}
                    '''
                    await chat.send_message(text=reply_text, disable_web_page_preview=False)
                else:
                    result = re.sub(r"([_*\[\]()~`>\#\+\-=|\.!])", r"\\\1", result)
                    reply_markdown = f'''
[{update.effective_user.first_name}](tg://user?id={update.effective_user.id})
Your URL contains tracking parameters and has been deleted and modified:
    
{result}
                    '''
                    await update.effective_message.reply_text(text=reply_markdown, parse_mode=ParseMode.MARKDOWN_V2,
                                                              disable_web_page_preview=False)
                await update.effective_message.delete()
            else:
                logging.debug(f'{log_prefix}: message not stripped')

    elif chat.type == Chat.CHANNEL:

        logging.info(f'{log_prefix}: got message')
        is_modified, result = strip_text(update.effective_message)
        if is_modified:
            logging.info(f'{log_prefix}: message stripped')
            await update.effective_message.edit_text(text=result, disable_web_page_preview=False)
        else:
            logging.debug(f'{log_prefix}: message not stripped')


class TelegramUrlTrackingStripper:

    def __init__(self, token: str, db_path: str) -> None:
        self.db = Database(db_path)
        self.app = ApplicationBuilder().token(token).build()

    def run(self):
        self.app.run_polling()


if __name__ == '__main__':

    token = os.environ['TOKEN']
    if not token:
        logging.fatal('Environment variable TOKEN is not set, exiting...')
        exit(-1)

    db = Database('data.db')

    application = ApplicationBuilder().token(token).build()

    start_handler = CommandHandler('start', start)
    application.add_handler(start_handler)

    enable_handler = CommandHandler('enable', enable)
    application.add_handler(enable_handler)

    disable_handler = CommandHandler('disable', disable)
    application.add_handler(disable_handler)

    meow_handler = CommandHandler('meow', meow)
    application.add_handler(meow_handler)

    msg_handler = MessageHandler(filters=(~filters.VIA_BOT) & filters.TEXT & (~filters.COMMAND), callback=msg_handler)
    application.add_handler(msg_handler)

    application.run_polling()
