import asyncio
import csv
import json
import os
import time
import psutil
import numpy as np
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.responses import PlainTextResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sklearn.ensemble import IsolationForest
import pickle
from datetime import datetime
import logging
from typing import Dict, List
import uuid
from ping3 import ping
from contextlib import asynccontextmanager
from collections import deque
import threading
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request as GoogleRequest
from pdf2image import convert_from_bytes
from dotenv import load_dotenv
import base64
from PIL import Image
import io
import requests
import whois
import re
from urllib.parse import urlparse
import pandas as pd
import tldextract
import uvicorn

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logging.getLogger('googleapiclient.discovery').setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

load_dotenv()

app = FastAPI(title="Security Dashboard API with Network Monitoring and Phishing Detection")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

class WebSocketManager:
    def __init__(self):
        self.clients: Dict[str, WebSocket] = {}

    def connect(self, websocket: WebSocket, client_id: str):
        self.clients[client_id] = websocket
        logger.info(f"Connected WebSocket for client_id: {client_id}")

    def disconnect(self, client_id: str):
        if client_id in self.clients:
            del self.clients[client_id]
            logger.info(f"Disconnected WebSocket for client_id: {client_id}")

    async def send_to_client(self, client_id: str, message: dict):
        if client_id in self.clients:
            try:
                await self.clients[client_id].send_json(message)
                logger.debug(f"Sent message to {client_id}: {message}")
            except Exception as e:
                logger.error(f"Error sending message to {client_id}: {str(e)}")
                self.disconnect(client_id)

ws_manager = WebSocketManager()
app.state.ws_manager = ws_manager

CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:8000/auth/google/callback")
SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile"
]

flow = Flow.from_client_config(
    {
        "web": {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "redirect_uris": [REDIRECT_URI],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    },
    scopes=SCOPES,
)

DATA_DIR = "data"
MODEL_DIR = "models"
CSV_FILE = os.path.join(DATA_DIR, "network_data.csv")
MODEL_FILE = os.path.join(MODEL_DIR, "rf_phishing_model.pkl")
ENCODER_FILE = os.path.join(MODEL_DIR, "tld_label_encoder.pkl")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

phishing_model = None
label_encoder = None
try:
    if os.path.exists(MODEL_FILE):
        with open(MODEL_FILE, "rb") as f:
            phishing_model = pickle.load(f)
        logger.info("Random Forest phishing model loaded successfully.")
    else:
        logger.warning(f"Model file {MODEL_FILE} not found in {os.getcwd()}")
except Exception as e:
    logger.error(f"Failed to load model from {MODEL_FILE}: {str(e)}")

try:
    if os.path.exists(ENCODER_FILE):
        with open(ENCODER_FILE, "rb") as f:
            label_encoder = pickle.load(f)
        logger.info("TLD label encoder loaded successfully.")
    else:
        logger.warning(f"Encoder file {ENCODER_FILE} not found in {os.getcwd()}")
except Exception as e:
    logger.error(f"Failed to load encoder from {ENCODER_FILE}: {str(e)}")

WHITELISTED_DOMAINS = [
    'webengage.com',
    'ampsp.webengage.co',
    'quora.com',
    'google.com',
    'googleapis.com',
    'facebook.com',
    'twitter.com',
    'linkedin.com',
    'youtube.com',
    'instagram.com',
    'pinterest.com',
    'reddit.com',
    'tiktok.com',
    'snapchat.com',
    'mixpanel.com',
    'segment.com',
    'amplitude.com',
    'hotjar.com',
    'doubleclick.net',
    'googletagmanager.com',
    'cloudflare.com',
    'amazonaws.com',
    'stripe.com',
    'paypal.com',
    'akamai.net',
    'fastly.com',
    'cdn.jsdelivr.net',
    'sentry.io',
    'newrelic.com',
    'intercom.com',
    'hubspot.com',
    'marketo.com',
    'salesforce.com',
    'zendesk.com',
    'slack.com',
    'discord.com',
    'microsoft.com',
    'office.com',
    'bing.com',
    'shopify.com',
    'woocommerce.com',
    'vimeo.com',
    'twilio.com',
    'sendgrid.com',
    'mailchimp.com',
    'adobe.com',
    'gettyimages.com',
    'shutterstock.com',
    'dropbox.com',
    'box.com',
    'wistia.com',
    'okta.com',
    'auth0.com',
    'algolia.com',
    'elastic.co',
    'atlassian.com',
    'jira.com',
    'confluence.com',
    'trello.com',
    'asana.com',
    'monday.com',
    'clickup.com',
    'notion.so',
    'airtable.com',
    'zapier.com',
    'ifttt.com',
    'datadog.com',
    'sumologic.com',
    'splunk.com',
    'pagerduty.com',
    'opsgenie.com',
    'statuspage.io',
    'github.com',
    'gitlab.com',
    'bitbucket.org',
    'npmjs.com',
    'yarnpkg.com',
    'docker.com',
    'kubernetes.io',
    'heroku.com',
    'netlify.com',
    'vercel.com',
    'digitalocean.com',
    'linode.com',
    'vultr.com',
    'gcp.cloud',
    'azure.com',
    'oracle.com',
    'ibm.com',
    'alibaba.com',
    'alibabacloud.com',
    'tencent.com',
    'baidu.com',
    'weixin.qq.com',
    'squareup.com',
    'squarespace.com',
    'wix.com',
    'webflow.com',
    'godaddy.com',
    'namecheap.com',
    'bluehost.com',
    'wordpress.com',
    'medium.com',
    'tumblr.com',
    'blogger.com',
    'patreon.com',
    'kickstarter.com',
    'indiegogo.com',
    'eventbrite.com',
    'meetup.com',
    'calendly.com',
    'docusign.com',
    'hellosign.com',
    'zoom.us',
    'webex.com',
    'gotomeeting.com',
    'skype.com',
    'telegram.org',
    'whatsapp.com',
    'signal.org',
    'viber.com',
    'line.me',
    'kakao.com',
    'zoho.com',
    'freshdesk.com',
    'freshworks.com',
    'servicenow.com',
    'snowflake.com',
    'tableau.com',
    'looker.com',
    'powerbi.microsoft.com',
    'qlik.com',
    'sisense.com',
    'docusaurus.io',
    'gatsbyjs.com',
    'nextjs.org',
    'nuxtjs.org',
    'vuejs.org',
    'reactjs.org',
    'angular.io',
    'svelte.dev',
    'emberjs.com',
    'meteor.com',
    'google.co.uk',
    'google.co.in',
    'google.de',
    'google.fr',
    'google.jp',
    'google.com.au',
    'google.ca',
    'google.com.br',
    'google.es',
    'google.it',
    'amazon.co.uk',
    'amazon.de',
    'amazon.fr',
    'amazon.co.jp',
    'amazon.in',
    'amazon.com.au',
    'amazon.ca',
    'amazon.es',
    'amazon.it',
    'amazon.com.br',
    's3.amazonaws.com',
    'ec2.amazonaws.com',
    'lambda.amazonaws.com',
    'rds.amazonaws.com',
    'dynamodb.amazonaws.com',
    'cloudfront.net',
    'gstatic.com',
    'maps.google.com',
    'analytics.google.com',
    'ads.google.com',
    'fonts.googleapis.com',
    'storage.googleapis.com',
    'compute.googleapis.com',
    'firebase.google.com',
    'appengine.google.com',
    'typeform.com',
    'surveymonkey.com',
    'qualtrics.com',
    'formstack.com',
    'jotform.com',
    'canva.com',
    'figma.com',
    'sketch.com',
    'invisionapp.com',
    'miro.com',
    'mural.co',
    'slack-edge.com',
    'cdn.shopify.com',
    'assets.shopify.com',
    'stripe.network',
    'api.stripe.com',
    'js.stripe.com',
    'checkout.stripe.com',
    'pay.google.com',
    'payments.google.com',
    'clarity.ms',
    'bat.bing.com',
    'c.bing.com',
    'linkedinmarketing.com',
    'ads.linkedin.com',
    'business.linkedin.com',
    'pinterestads.com',
    'ads.reddit.com',
    'ads.tiktok.com',
    'analytics.tiktok.com',
    'vimeocdn.com',
    'player.vimeo.com',
    'mailgun.com',
    'postmarkapp.com',
    'sparkpost.com',
    'mandrillapp.com',
    'ses.amazonaws.com',
    'smtp.sendgrid.net',
    'api.sendgrid.com',
    'api.hubspot.com',
    'forms.hubspot.com',
    'track.hubspot.com',
    'js.hubspot.com',
    'api.intercom.io',
    'widget.intercom.io',
    'js.intercomcdn.com',
    'api.zapier.com',
    'hooks.zapier.com',
    'cdn.zapier.com',
    'api.airtable.com',
    'dl.airtable.com',
    'api.notion.com',
    's3.notion.so',
    'cdn.notion.so',
    'api.trello.com',
    'trello-attachments.s3.amazonaws.com',
    'api.atlassian.com',
    'id.atlassian.com',
    'bitbucket.io',
    'sourcetreeapp.com',
    'status.atlassian.com',
    'support.atlassian.com',
    'developer.atlassian.com',
    'marketplace.atlassian.com',
    'auth.docker.com',
    'registry.docker.com',
    'hub.docker.com',
    'docs.docker.com',
    'cdn.auth0.com',
    'auth0.auth0.com',
    'cdn.okta.com',
    'developer.okta.com',
    'api.algolia.com',
    'cdn.algolia.net',
    'dashboard.algolia.com',
    'api.elastic.co',
    'kibana.elastic.co',
    'logs.elastic.co',
    'apm.elastic.co',
    'sentrycdn.com',
    'browser.sentry-cdn.com',
    'app.getsentry.com',
    'cdn.datadoghq.com',
    'app.datadoghq.com',
    'api.datadoghq.com',
    'cdn.sumologic.com',
    'api.sumologic.com',
    'events.sumologic.com',
    'cdn.splunk.com',
    'splunkcloud.com',
    'api.pagerduty.com',
    'events.pagerduty.com',
    'cdn.opsgenie.com',
    'api.opsgenie.com',
    'app.statuspage.io',
    'cdn.statuspage.io',
    'api.github.com',
    'raw.githubusercontent.com',
    'avatars.githubusercontent.com',
    'codeload.github.com',
    'api.gitlab.com',
    'cdn.gitlab-static.net',
    'about.gitlab.com',
    's3.gitlab.com',
    'cdn.bitbucket.org',
    'api.bitbucket.org',
    'status.bitbucket.org',
    'cdn.npmjs.com',
    'registry.npmjs.org',
    'api.yarnpkg.com',
    'cdn.yarnpkg.com',
    'cdn.netlify.com',
    'app.netlify.com',
    'api.netlify.com',
    'cdn.vercel.app',
    'vercel.app',
    'api.vercel.com',
    'app.digitalocean.com',
    'api.digitalocean.com',
    'cdn.digitalocean.com',
    'cloud.linode.com',
    'api.linode.com',
    'cdn.vultr.com',
    'api.vultr.com',
    'console.cloud.google.com',
    'cloud.google.com',
    'storage.cloud.google.com',
    'iam.googleapis.com',
    'pubsub.googleapis.com',
    'bigquery.googleapis.com',
    'functions.googleapis.com',
    'run.googleapis.com',
    'artifactregistry.googleapis.com',
    'logging.googleapis.com',
    'monitoring.googleapis.com',
    'azure.microsoft.com',
    'portal.azure.com',
    'management.azure.com',
    'blob.core.windows.net',
    'queue.core.windows.net',
    'table.core.windows.net',
    'file.core.windows.net',
    'cdn.oracle.com',
    'cloud.oracle.com',
    'oci.oraclecloud.com',
    'objectstorage.us-phoenix-1.oraclecloud.com',
    'iaas.us-phoenix-1.oraclecloud.com',
    'cloud.ibm.com',
    'api.ibm.com',
    'cloud-object-storage.appdomain.cloud',
    's3.us-south.cf.cloud.ibm.com',
    'alibabacloud.com',
    'ecs.aliyuncs.com',
    'oss.aliyuncs.com',
    'rds.aliyuncs.com',
    'slb.aliyuncs.com',
    'cdn.tencentcloud.com',
    'cloud.tencent.com',
    'cos.ap-shanghai.myqcloud.com',
    'cdn.baidubce.com',
    'bcebos.com',
    'cloud.baidu.com',
    'openapi.weixin.qq.com',
    'mp.weixin.qq.com',
    'developers.weixin.qq.com',
    'square.site',
    'cdn.squarespace.com',
    'assets.squarespace.com',
    'cdn.wixstatic.com',
    'editor.wix.com',
    'siteassets.wixapps.net',
    'cdn.webflow.com',
    'assets.webflow.com',
    'api.godaddy.com',
    'sso.godaddy.com',
    'cdn.namecheap.com',
    'api.namecheap.com',
    'cdn.bluehost.com',
    'cpanel.bluehost.com',
    's0.wordpress.com',
    'public-api.wordpress.com',
    'stats.wordpress.com',
    's1.wordpress.com',
    's2.wordpress.com',
    's3.wordpress.com',
    'wpcom.files.wordpress.com',
    'medium.build',
    'cdn-images-1.medium.com',
    'cdn-static-1.medium.com',
    'tumblr.com',
    'assets.tumblr.com',
    'safe.tumblr.com',
    'blogger.google.com',
    'cdn.patreon.com',
    'api.patreon.com',
    'cdn.kickstarter.com',
    'api.kickstarter.com',
    'cdn.indiegogo.com',
    'api.indiegogo.com',
    'cdn.eventbrite.com',
    'api.eventbrite.com',
    'cdn.meetup.com',
    'api.meetup.com',
    'cdn.calendly.com',
    'api.calendly.com',
    'cdn.docusign.com',
    'api.docusign.com',
    'cdn.hellosign.com',
    'api.hellosign.com',
    'cdn.zoom.us',
    'api.zoom.us',
    'cdn.webex.com',
    'api.webex.com',
    'cdn.gotomeeting.com',
    'api.gotomeeting.com',
    'cdn.skype.com',
    'api.skype.com',
    'cdn.telegram.org',
    'api.telegram.org',
    'web.whatsapp.com',
    'api.whatsapp.com',
    'cdn.signal.org',
    'api.signal.org',
    'cdn.viber.com',
    'api.viber.com',
    'cdn.line.me',
    'api.line.me',
    'cdn.kakao.com',
    'api.kakao.com',
    'crm.zoho.com',
    'desk.zoho.com',
    'books.zoho.com',
    'invoice.zoho.com',
    'cdn.freshdesk.com',
    'api.freshdesk.com',
    'cdn.freshworks.com',
    'api.freshworks.com',
    'cdn.servicenow.com',
    'api.servicenow.com',
    'cdn.snowflake.com',
    'app.snowflake.com',
    'cdn.tableau.com',
    'api.tableau.com',
    'cdn.looker.com',
    'api.looker.com',
    'cdn.powerbi.microsoft.com',
    'app.powerbi.com',
    'cdn.qlik.com',
    'api.qlik.com',
    'cdn.sisense.com',
    'api.sisense.com',
    'cdn.docusaurus.io',
    'docusaurus.io',
    'cdn.gatsbyjs.com',
    'cdn.nextjs.org',
    'cdn.nuxtjs.org',
    'cdn.vuejs.org',
    'cdn.reactjs.org',
    'cdn.angular.io',
    'cdn.svelte.dev',
    'cdn.emberjs.com',
    'cdn.meteor.com',
    'cdn.typeform.com',
    'api.typeform.com',
    'cdn.surveymonkey.com',
    'api.surveymonkey.com',
    'cdn.qualtrics.com',
    'api.qualtrics.com',
    'cdn.formstack.com',
    'api.formstack.com',
    'cdn.jotform.com',
    'api.jotform.com',
    'cdn.canva.com',
    'api.canva.com',
    'cdn.figma.com',
    'api.figma.com',
    'cdn.sketch.com',
    'api.sketch.com',
    'cdn.invisionapp.com',
    'api.invisionapp.com',
    'cdn.miro.com',
    'api.miro.com',
    'cdn.mural.co',
    'api.mural.co',
    'nytimes.com',
    'washingtonpost.com',
    'cnn.com',
    'bbc.com',
    'theguardian.com',
    'forbes.com',
    'bloomberg.com',
    'wsj.com',
    'reuters.com',
    'apnews.com',
    'netflix.com',
    'hulu.com',
    'disneyplus.com',
    'hbomax.com',
    'spotify.com',
    'apple.com',
    'music.apple.com',
    'itunes.apple.com',
    'icloud.com',
    'ebay.com',
    'etsy.com',
    'aliexpress.com',
    'walmart.com',
    'target.com',
    'bestbuy.com',
    'costco.com',
    'macys.com',
    'nike.com',
    'adidas.com',
    'underarmour.com',
    'lulu.com',
    'zara.com',
    'hm.com',
    'gap.com',
    'levis.com',
    'paypal.me',
    'venmo.com',
    'cash.app',
    'zellepay.com',
    'transferwise.com',
    'revolut.com',
    'monzo.com',
    'n26.com',
    'chime.com',
    'robinhood.com',
    'coinbase.com',
    'binance.com',
    'kraken.com',
    'gemini.com',
    'bitstamp.net',
    'blockchain.com',
    'trezor.io',
    'ledger.com',
    'metamask.io',
    'opensea.io',
    'rarible.com',
    'foundation.app',
    'niftygateway.com',
    'superrare.co',
    'makersplace.com',
    'strava.com',
    'fitbit.com',
    'garmin.com',
    'myfitnesspal.com',
    'peloton.com',
    'zwift.com',
    'whoop.com',
    'runkeeper.com',
    'mapmyrun.com',
    'komoot.com',
    'coursera.org',
    'edx.org',
    'udemy.com',
    'khanacademy.org',
    'codecademy.com',
    'freecodecamp.org',
    'pluralsight.com',
    'udacity.com',
    'skillshare.com',
    'masterclass.com',
    'duolingo.com',
    'rosettastone.com',
    'babbel.com',
    'memrise.com',
    'quizlet.com',
    'chegg.com',
    'grammarly.com',
    'turnitin.com',
    'canvaslms.com',
    'blackboard.com',
    'moodle.org',
    'scholastic.com',
    'pearson.com',
    'wiley.com',
    'springer.com',
    'elsevier.com',
    'jstor.org',
    'researchgate.net',
    'academia.edu',
    'sciencedirect.com',
    'pubmed.gov',
    'nih.gov',
    'cdc.gov',
    'who.int',
    'mayoclinic.org',
    'webmd.com',
    'healthline.com',
    'medscape.com',
    'clevelandclinic.org',
    'hopkinsmedicine.org',
    'redcross.org',
    'unicef.org',
    'amnesty.org',
    'greenpeace.org',
    'wwf.org',
    'savethechildren.org',
    'oxfam.org',
    'charitynavigator.org',
    'gofundme.com',
    'donorschoose.org',
    'tripadvisor.com',
    'expedia.com',
    'booking.com',
    'airbnb.com',
    'vrbo.com',
    'hotels.com',
    'kayak.com',
    'orbitz.com',
    'travelocity.com',
    'priceline.com',
    'uber.com',
    'lyft.com',
    'doordash.com',
    'ubereats.com',
    'grubhub.com',
    'postmates.com',
    'instacart.com',
    'shipt.com',
    'grocery.walmart.com',
    'fresh.amazon.com',
    'fedex.com',
    'ups.com',
    'usps.com',
    'dhl.com',
    'tnt.com',
    'bluedart.com',
    'aramex.com',
    'canadapost.ca',
    'royalmail.com',
    'auspost.com.au',
    'weather.com',
    'accuweather.com',
    'wunderground.com',
    'noaa.gov',
    'metoffice.gov.uk',
    'bom.gov.au',
    'weather.gov',
    'nasa.gov',
    'space.com',
    'esa.int',
    'isro.gov.in',
    'csa.gc.ca',
    'jaxa.jp',
    'roscosmos.ru',
    'spacex.com',
    'blueorigin.com',
    'virgin.com',
    'boeing.com',
    'airbus.com',
    'lockheedmartin.com',
    'raytheon.com',
    'northropgrumman.com',
    'generalatomics.com',
    'tesla.com',
    'ford.com',
    'gm.com',
    'toyota.com',
    'honda.com',
    'bmw.com',
    'mercedes-benz.com',
    'audi.com',
    'volkswagen.com',
    'hyundai.com',
    'kia.com',
    'nissan.com',
    'subaru.com',
    'mazda.com',
    'ferrari.com',
    'lamborghini.com',
    'porsche.com',
    'bugatti.com',
    'mclaren.com',
    'astonmartin.com',
    'rolls-royce.com',
    'bentley.com',
    'jaguar.com',
    'landrover.com',
    'volvo.com',
    'saab.com',
    'peugeot.com',
    'citroen.com',
    'renault.com',
    'fiat.com',
    'alfa-romeo.com',
    'maserati.com',
    'chrysler.com',
    'dodge.com',
    'jeep.com',
    'ramtrucks.com',
    'buick.com',
    'cadillac.com',
    'chevrolet.com',
    'gmc.com',
    'lincoln.com',
    'acura.com',
    'infiniti.com',
    'lexus.com',
    'genesis.com',
    'lotus.com',
    'byd.com',
    'nio.com',
    'xpeng.com',
    'lixiang.com',
    'geely.com',
    'changan.com',
    'greatwall.com',
    'haval.com',
    'jacmotors.com',
    'mgmotor.com',
    'tata.com',
    'mahindra.com',
    'suzuki.com',
    'isuzu.com',
    'daihatsu.com',
    'mitsubishi.com',
    'ssangyong.com',
    'proton.com',
    'perodua.com',
    'maruti.com',
    'skoda.com',
    'seat.com',
    'cupra.com',
    'lancia.com',
    'opel.com',
    'vauxhall.com',
    'dsautomobiles.com',
    'smart.com',
    'mini.com',
    'polestar.com',
    'rivian.com',
    'lucidmotors.com',
    'fisker.com',
    'bollinger.com',
    'lordstown.com',
    'canoo.com',
    'aptera.com',
    'sono.com',
    'lightyear.one',
    'pininfarina.com',
    'automobili-pininfarina.com',
    'karma.com',
    'shelby.com',
    'saleen.com',
    'hennessey.com',
    'koenigsegg.com',
    'pagani.com',
    'rimac.com',
    'czinger.com',
    'deus.com',
    'drako.com',
    'faraday.com',
    'ff.com',
    'icon.com',
    'localmotors.com',
    'lyonheart.com',
    'morgan-motor.com',
    'noble.com',
    'radical.com',
    'rossion.com',
    'spyker.com',
    'tvr.com',
    'ultima.com',
    'westfield.com',
    'zenvo.com',
    'arash.com',
    'ariel.com',
    'ascari.com',
    'brabham.com',
    'briggs.com',
    'caterham.com',
    'donkervoort.com',
    'gordonmurray.com',
    'gumper.com',
    'lotus-cars.com',
    'mazzanti.com',
    'panoz.com',
    'puritalia.com',
    'scuderiavittoria.com',
    'sin.com',
    'spartan.com',
    'tramontana.com',
    'vuhl.com',
    'wiesmann.com',
    'elemental.com',
    'bac.com',
    'detomaso.com',
    'iso.com',
    'joss.com',
    'kTM.com',
    'lister.com',
    'lynkco.com',
    'mullen.com',
    'nismo.com',
    'ora.com',
    'qoros.com',
    'ravon.com',
    'srt.com',
    'togg.com',
    'vinfast.com',
    'wey.com',
    'yudo.com',
    'zotye.com',
    'abarth.com',
    'alpina.com',
    'brabus.com',
    'carlsson.com',
    'gemballa.com',
    'hamann.com',
    'lorinser.com',
    'mansory.com',
    'mtm.com',
    'ruf.com',
    'startech.com',
    'techart.com',
    'trion.com',
    'vector.com',
    'venturi.com',
    'vencer.com',
    'callaway.com',
    'dmc.com',
    'eddesign.com',
    'fornasari.com',
    'giannini.com',
    'italdesign.com',
    'lancia.com',
    'osca.com',
    'touring.com',
    'zagato.com',
    'abt.com',
    'ac-schnitzer.com',
    'hartge.com',
    'kelleners.com',
    'lumma.com',
    'rieger.com',
    'schnitzer.com',
    'steinmetz.com',
    'wald.com',
    'yes.com',
    'zender.com',
    '9ff.com',
    'artega.com',
    'bitter.com',
    'borgward.com',
    'deutsch-bonnet.com',
    'facel.com',
    'hommell.com',
    'matra.com',
    'mega.com',
    'monaco.com',
    'pgo.com',
    'salmson.com',
    'siata.com',
    'talbot.com',
    'turbo.com',
    'vau.com',
    'berliet.com',
    'bugatti.fr',
    'delage.com',
    'delahaye.com',
    'hotchkiss.com',
    'ligier.com',
    'panther.com',
    'salmsons.com',
    'simca.com',
    'venturi.fr',
    'aixam.com',
    'bellier.com',
    'chatenet.com',
    'jdm.fr',
    'microcar.com',
    'exagon.com',
    'gta.com',
    'leopard.com',
    'loremo.com',
    'mindset.com',
    'nice.com',
    'th!nk.com',
    'valmet.com',
    'wartburg.com',
    'zaz.com',
    'zastava.com',
    'yugo.com',
    'barkas.com',
    'dacia.com',
    'fso.com',
    'gaz.com',
    'lada.com',
    'moskvitch.com',
    'uaz.com',
    'volga.com',
    'zaporozhets.com',
    'avtovaz.com',
    'kamaz.com',
    'zil.com',
    'byton.com',
    'chery.com',
    'dongfeng.com',
    'faw.com',
    'gac.com',
    'haima.com',
    'hongqi.com',
    'jmc.com',
    'lifan.com',
    'qorosauto.com',
    'saicmotor.com',
    'wuling.com',
    'xiali.com',
    'yutong.com',
    'zhongtong.com',
    'zxauto.com',
    'brilliance.com',
    'foton.com',
    'higer.com',
    'kinglong.com',
    'youngman.com',
    'ankai.com',
    'beiben.com',
    'camc.com',
    'dayun.com',
    'golden-dragon.com',
    'higerbus.com',
    'jac.com',
    'shacman.com',
    'sinotruk.com',
    'yaxing.com',
    'yinlong.com',
    'zhonghua.com',
    'asia-motor.com',
    'daewoo.com',
    'hyundai-motor.com',
    'kia-motors.com',
    'samsung.com',
    'genesis-motor.com',
    'inokom.com',
    'naza.com',
    'tdm.com',
    'tan-chong.com',
    'asia-motors.com',
    'galloper.com',
    'korea-motor.com',
    'pungwoo.com',
    'ssangyong-motor.com',
    'daewoo-bus.com',
    'doosan.com',
    'hino.com',
    'isuzu-motors.com',
    'mazda-motors.com',
    'mitsubishi-motors.com',
    'nissan-motors.com',
    'subaru-corp.com',
    'suzuki-motors.com',
    'toyota-motors.com',
    'honda-motors.com',
    'yamaha.com',
    'kawasaki.com',
    'fuso.com',
    'udtrucks.com',
    'ashokleyland.com',
    'bajaj.com',
    'eicher.com',
    'force.com',
    'hero.com',
    'hindustan.com',
    'premier.com',
    'royal-enfield.com',
    'smlisuzu.com',
    'tvs.com',
    'atulev.com',
    'bharatbenz.com',
    'mahindra-rise.com',
    'maruti-suzuki.com',
    'tata-motors.com',
    'volvo-cars.com',
    'scania.com',
    'man.com',
    'iveco.com',
    'daf.com',
    'kenworth.com',
    'mack.com',
    'navistar.com',
    'paccar.com',
    'peterbilt.com',
    'freightliner.com',
    'westernstar.com',
    'hino-motors.com',
    'ud-trucks.com',
    'fuso-trucks.com',
    'isuzu-trucks.com',
    'tata-trucks.com',
    'eicher-trucks.com',
    'ashok-leyland.com',
    'bharat-benz.com',
    'mahindra-trucks.com',
    'sml-isuzu.com',
    'volvo-trucks.com',
    'scania-trucks.com',
    'man-trucks.com',
    'iveco-trucks.com',
    'daf-trucks.com',
    'kenworth-trucks.com',
    'mack-trucks.com',
    'navistar-trucks.com',
    'paccar-trucks.com',
    'peterbilt-trucks.com',
    'freightliner-trucks.com',
    'westernstar-trucks.com',
    'hino-trucks.com',
    'udtrucks-trucks.com',
    'fuso-trucks.com',
    'isuzu-trucks.com',
    'tata-trucks.com',
    'eicher-trucks.com',
    'ashok-leyland.com',
    'bharat-benz.com',
    'mahindra-trucks.com',
    'sml-isuzu.com',
    'volvo-trucks.com',
    'scania-trucks.com',
    'man-trucks.com',
    'iveco-trucks.com',
    'daf-trucks.com'
]

def extract_features(url):
    try:
        parsed = tldextract.extract(url)
        domain = parsed.domain
        tld = parsed.suffix
        subdomain = parsed.subdomain
        hostname = f"{subdomain}.{domain}.{tld}" if subdomain else f"{domain}.{tld}"
        features = {
            'url_length': len(url),
            'domain_length': len(hostname),
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'has_suspicious_keyword': int(any(keyword in url.lower() for keyword in ['login', 'verify', 'account', 'secure', 'update', 'bank', 'paypal', 'signin'])),
            'num_subdomains': len(subdomain.split('.')) if subdomain else 0,
            'has_https': int(url.lower().startswith('https')),
            'has_digits_in_domain': int(any(char.isdigit() for char in domain)),
            'tld': tld if tld else 'com',
            'path_length': len(url.split(hostname)[-1]),
            'num_query_params': len(url.split('?')[-1].split('&')) if '?' in url else 0,
            'has_ip_address': int(bool(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url)))
        }
        return features
    except Exception as e:
        logger.error(f"Error extracting features for URL {url}: {str(e)}")
        return None

def get_authenticated_service(access_token: str, refresh_token: str = None):
    try:
        if not access_token:
            raise HTTPException(status_code=400, detail="Access token is required")
        credentials = Credentials(
            token=access_token,
            refresh_token=refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scopes=SCOPES
        )
        if credentials.expired and credentials.refresh_token:
            logger.info("Access token expired, attempting to refresh")
            credentials.refresh(GoogleRequest())
            logger.info("Access token refreshed successfully")
        return build("gmail", "v1", credentials=credentials, cache_discovery=False), credentials.token
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")

def check_domain_reputation(url):
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        has_ssl = url.startswith("https://")
        is_responsive = response.status_code == 200
        return has_ssl and is_responsive
    except requests.RequestException:
        return False

def check_whois_domain(url):
    try:
        domain = urlparse(url).netloc
        if not domain:
            logger.warning(f"Could not extract domain from URL: {url}")
            return {"is_suspicious": True, "details": "Invalid or unparsable URL"}
        w = whois.whois(domain)
        creation_date = w.get("creation_date")
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not creation_date:
            return {"is_suspicious": True, "details": "No creation date available"}
        age_days = (datetime.now() - creation_date).days
        is_recent = age_days < 180
        registrar = w.get("registrar", "").lower()
        suspicious_registrars = ["publicdomainregistry"]
        is_suspicious_registrar = any(r in registrar for r in suspicious_registrars)
        status = w.get("status", [])
        is_active = bool(status and any(any(s.lower().find(status) != -1 for status in [
            "active", "ok", "clienttransferprohibited", "clientdeleteprohibited",
            "clientupdateprohibited", "clientrenewprohibited", "servertransferprohibited",
            "serverdeleteprohibited", "serverupdateprohibited"
        ]) for s in status))
        details = f"Domain age: {age_days} days, Registrar: {registrar}, Active: {is_active}"
        is_suspicious = is_recent or is_suspicious_registrar or not is_active
        return {"is_suspicious": is_suspicious, "details": details}
    except Exception as e:
        logger.error(f"WHOIS check failed for {url}: {str(e)}")
        return {"is_suspicious": True, "details": f"WHOIS lookup failed: {str(e)}"}

def check_google_safe_browsing(url):
    if not SAFE_BROWSING_API_KEY:
        logger.error("Google Safe Browsing API key not provided")
        return False
    payload = {
        "client": {"clientId": "phishing-url-detection-452208", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(
            SAFE_BROWSING_URL,
            params={"key": SAFE_BROWSING_API_KEY},
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),
            timeout=5
        )
        if response.status_code == 200:
            result = response.json()
            is_threat = bool(result.get("matches"))
            logger.info(f"URL {url} is threat: {is_threat}")
            return is_threat
        logger.warning(f"Safe Browsing API error: {response.status_code} - {response.text}")
        return False
    except Exception as e:
        logger.error(f"Error checking Safe Browsing for {url}: {str(e)}")
        return False

def check_virustotal(url):
    if not VIRUSTOTAL_API_KEY:
        logger.error("VirusTotal API key not provided")
        return {"is_malicious": False, "details": "VirusTotal API key not configured"}
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY, "Accept": "application/json"}
        response = requests.get(f"{VIRUSTOTAL_URL}/{url_id}", headers=headers, timeout=5)
        if response.status_code == 200:
            result = response.json()
            stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)
            is_malicious = malicious_count > 0 or suspicious_count > 0
            details = f"Malicious: {malicious_count}, Suspicious: {suspicious_count}"
            logger.info(f"VirusTotal result for {url}: {details}")
            return {"is_malicious": is_malicious, "details": details}
        elif response.status_code == 404:
            submit_response = requests.post(VIRUSTOTAL_URL, headers=headers, data={"url": url}, timeout=5)
            if submit_response.status_code == 200:
                return {"is_malicious": False, "details": "URL submitted for analysis, check later"}
            return {"is_malicious": False, "details": f"VirusTotal submission error: {submit_response.text}"}
        return {"is_malicious": False, "details": f"VirusTotal API error: {response.text}"}
    except Exception as e:
        logger.error(f"Error checking VirusTotal for {url}: {str(e)}")
        return {"is_malicious": False, "details": f"Error: {str(e)}"}

def check_phishtank(url):
    if not PHISHTANK_API_KEY:
        logger.warning("PhishTank API key not provided")
        return {"is_phishing": False, "details": "PhishTank API key not configured"}
    try:
        response = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": url, "format": "json", "app_key": PHISHTANK_API_KEY},
            timeout=5
        )
        if response.status_code == 200:
            result = response.json()
            is_phishing = result.get("results", {}).get("valid", False)
            details = f"Valid={is_phishing}, Verified={result.get('results', {}).get('verified', False)}"
            logger.info(f"PhishTank result for {url}: {details}")
            return {"is_phishing": is_phishing, "details": details}
        return {"is_phishing": False, "details": f"PhishTank API error: {response.text}"}
    except Exception as e:
        logger.error(f"PhishTank check failed for {url}: {str(e)}")
        return {"is_phishing": False, "details": f"PhishTank check failed: {str(e)}"}

def check_url(url):
    is_whitelisted = any(domain in url for domain in WHITELISTED_DOMAINS)
    safe_browsing_threat = check_google_safe_browsing(url)
    virustotal_result = check_virustotal(url)
    whois_result = check_whois_domain(url)
    phishtank_result = check_phishtank(url)
    virustotal_malicious = virustotal_result["is_malicious"]
    whois_suspicious = whois_result["is_suspicious"]
    phishtank_phishing = phishtank_result["is_phishing"]
    parsed = urlparse(url)
    suspicious_keywords = ['login', 'verify', 'account', 'secure', 'update', 'bank', 'paypal', 'signin']
    has_suspicious_keyword = any(keyword in url.lower() for keyword in suspicious_keywords)
    num_query_params = len(parsed.query.split('&')) if parsed.query else 0
    num_subdomains = len(parsed.netloc.split('.')) - 2 if parsed.netloc else 0
    has_ip_address = bool(re.match(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', parsed.netloc))
    is_suspicious_heuristic = (
        (has_suspicious_keyword and num_query_params > 5) or
        num_query_params > 10 or
        num_subdomains > 2 or
        has_ip_address
    )
    model_phishing = False
    model_probability = 0.5
    if phishing_model and label_encoder:
        try:
            features = extract_features(url)
            if features:
                features_df = pd.DataFrame([features])
                features_df['tld'] = features_df['tld'].apply(
                    lambda x: x if x in label_encoder.classes_ else 'com'
                )
                features_df['tld'] = label_encoder.transform(features_df['tld'])
                prediction = phishing_model.predict(features_df)[0]
                model_probability = phishing_model.predict_proba(features_df)[0][1]
                model_phishing = prediction == 1 and model_probability > 0.5
                logger.info(f"Model prediction for {url}: Phishing={model_phishing}, Probability={model_probability:.2f}")
            else:
                logger.warning(f"Feature extraction failed for {url}")
        except Exception as e:
            logger.error(f"Model prediction failed for {url}: {str(e)}")
    is_phishing = (
        safe_browsing_threat or
        virustotal_malicious or
        whois_suspicious or
        phishtank_phishing or
        is_suspicious_heuristic or
        model_phishing
    )
    if is_whitelisted and not (safe_browsing_threat or virustotal_malicious or phishtank_phishing):
        is_phishing = False
    threat_details = (
        f"Model prediction={'Phishing' if model_phishing else 'Safe'}, Probability={model_probability:.2f}, "
        f"Safe Browsing={'Threat' if safe_browsing_threat else 'Safe'}, "
        f"VirusTotal={virustotal_result['details']}, "
        f"WHOIS={whois_result['details']}, "
        f"PhishTank={phishtank_result['details']}, "
        f"Heuristics=Suspicious: {is_suspicious_heuristic}" + (", Whitelisted" if is_whitelisted else "")
    )
    confidence = model_probability if model_phishing else 0.5
    if is_suspicious_heuristic:
        confidence = max(confidence, 0.7)
    if safe_browsing_threat or virustotal_malicious or phishtank_phishing:
        confidence = max(confidence, 0.9)
    if whois_suspicious:
        confidence = max(confidence, 0.8)
    if is_whitelisted and not (safe_browsing_threat or virustotal_malicious or phishtank_phishing):
        confidence = 0.0
    logger.info(f"Phishing prediction for {url}: is_phishing={is_phishing}, confidence={confidence:.2f}")
    return {
        "url": url,
        "is_phishing": bool(is_phishing),
        "confidence": float(confidence),
        "threatDetails": threat_details,
        "safeBrowsingThreat": bool(safe_browsing_threat),
        # "virustotalDetails": virustotal_result["details"],
        # "whoisDetails": whois_result["details"],
        # "phishtankDetails": phishtank_result["details"]
    }

def convert_numpy_types(obj):
    if isinstance(obj, np.bool_):
        return bool(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, dict):
        return {k: convert_numpy_types(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(item) for item in obj]
    return obj

@app.get("/")
async def home():
    return {"message": "Security Dashboard API with Network Monitoring and Phishing Detection"}


@app.get("/auth/google")
async def auth_google():
    flow.redirect_uri = REDIRECT_URI
    authorization_url, _ = flow.authorization_url(prompt="consent", include_granted_scopes="true")
    logger.info(f"Generated authorization URL: {authorization_url}")
    return {"auth_url": authorization_url}

@app.get("/auth/google/callback")
async def auth_google_callback(request: Request):
    try:
        query_params = dict(request.query_params)
        if "code" not in query_params:
            raise HTTPException(status_code=400, detail="Authorization code not found")
        flow.redirect_uri = REDIRECT_URI
        flow.fetch_token(code=query_params["code"])
        credentials = flow.credentials
        logger.info("Successfully authenticated user")
        return RedirectResponse(
            url=f"http://localhost:5173/dashboard?access_token={credentials.token}&refresh_token={credentials.refresh_token}"
        )
    except Exception as e:
        logger.error(f"OAuth2 Error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"OAuth2 Error: {str(e)}")

@app.get("/api/gmail/messages")
async def get_gmail_messages(
    access_token: str,
    refresh_token: str = None,
    max_results: int = 10,
    page_token: str = None
):
    try:
        logger.info("Fetching Gmail messages")
        service, new_access_token = get_authenticated_service(access_token, refresh_token)
        response = service.users().messages().list(
            userId="me",
            maxResults=max_results,
            pageToken=page_token
        ).execute()
        messages = response.get("messages", [])
        next_page_token = response.get("nextPageToken")
        email_details = []
        for msg in messages:
            logger.info(f"Fetching details for message ID: {msg['id']}")
            msg_data = service.users().messages().get(userId="me", id=msg["id"], format="full").execute()
            email_details.append(msg_data)
        logger.info(f"Fetched {len(email_details)} email details")
        return {
            "messages": email_details,
            "nextPageToken": next_page_token,
            "new_access_token": new_access_token if new_access_token != access_token else None
        }
    except HttpError as e:
        logger.error(f"Gmail API error: {str(e)}")
        if e.resp.status == 401:
            raise HTTPException(status_code=401, detail="Invalid or expired access token")
        raise HTTPException(status_code=500, detail=f"Gmail API error: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error in get_gmail_messages: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch emails: {str(e)}")

@app.get("/api/gmail/messages/{email_id}/attachments/{attachment_id}")
async def get_attachment(
    email_id: str,
    attachment_id: str,
    access_token: str,
    refresh_token: str = None
):
    try:
        logger.info(f"Fetching attachment {attachment_id} for email {email_id}")
        service, new_access_token = get_authenticated_service(access_token, refresh_token)
        attachment = service.users().messages().attachments().get(
            userId="me",
            messageId=email_id,
            id=attachment_id
        ).execute()
        data = attachment.get("data", "")
        if not data:
            logger.error(f"No data found for attachment {attachment_id}")
            raise HTTPException(status_code=404, detail=f"Attachment {attachment_id} has no data")
        standard_base64 = data.replace('-', '+').replace('_', '/')
        mime_type = "application/octet-stream"
        try:
            message = service.users().messages().get(
                userId="me", 
                id=email_id, 
                format="metadata",
                metadataHeaders=["Content-Type"]
            ).execute()
            for part in message.get('payload', {}).get('parts', []):
                if part.get('body', {}).get('attachmentId') == attachment_id:
                    mime_type = part.get('mimeType', mime_type)
                    break
        except Exception as e:
            logger.warning(f"Could not determine MIME type: {str(e)}")
        logger.info(f"Successfully fetched attachment {attachment_id}")
        return {
            "data": standard_base64,
            "mimeType": mime_type,
            "new_access_token": new_access_token if new_access_token != access_token else None
        }
    except HttpError as e:
        logger.error(f"Failed to fetch attachment {attachment_id}: {str(e)}")
        if e.resp.status == 404:
            raise HTTPException(status_code=404, detail=f"Attachment {attachment_id} not found")
        raise HTTPException(status_code=500, detail=f"Failed to fetch attachment: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error in get_attachment: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Unexpected error fetching attachment: {str(e)}")

@app.post("/api/extract-pdf-images")
async def extract_pdf_images(data: dict):
    pdf_data = data.get("pdfData")
    access_token = data.get("accessToken")
    if not pdf_data or not access_token:
        logger.error("Missing pdfData or accessToken")
        raise HTTPException(status_code=400, detail="pdfData and accessToken are required")
    try:
        service, new_access_token = get_authenticated_service(access_token)
    except HTTPException as e:
        logger.error(f"Authentication failed: {str(e)}")
        raise e
    try:
        pdf_bytes = base64.b64decode(pdf_data)
        images = convert_from_bytes(pdf_bytes, fmt='png')
        image_data = []
        for i, img in enumerate(images):
            buffered = io.BytesIO()
            img.save(buffered, format="PNG")
            img_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
            image_data.append({
                "mimeType": "image/png",
                "data": img_base64
            })
            logger.info(f"Extracted image {i+1} from PDF")
        return {
            "images": image_data,
            "new_access_token": new_access_token
        }
    except base64.binascii.Error as e:
        logger.error(f"Invalid base64 data for PDF: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Invalid base64 data: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to extract images from PDF: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to extract images: {str(e)}")

@app.post("/api/scan")
async def scan_content(data: dict):
    links = data.get("links", [])
    access_token = data.get("accessToken")
    if not access_token:
        logger.error("No access token provided in scan request")
        raise HTTPException(status_code=400, detail="Access token is required")
    try:
        service, new_access_token = get_authenticated_service(access_token)
    except HTTPException as e:
        logger.error(f"Authentication failed in scan endpoint: {str(e)}")
        raise e
    phishing_links = []
    for link in links:
        if not isinstance(link, str) or not link.startswith('http'):
            logger.warning(f"Skipping invalid link: {link}")
            continue
        result = check_url(link)
        phishing_links.append(convert_numpy_types(result))
    response = {
        "qrCodes": [],
        "phishingLinks": phishing_links,
        "new_access_token": new_access_token
    }
    return convert_numpy_types(response)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)