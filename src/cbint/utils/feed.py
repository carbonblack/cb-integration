import time
import base64
import logging
import threading

import cbint.utils.cbserver


def generate_icon(image_path):
    """
    Get the feed icon as a base64(png)
    returns None when not found
    """
    try:
        f = open(image_path)
        return base64.b64encode(f.read())
    except:
        return None


def generate_feed(feed_name, summary, tech_data, provider_url, icon_path, display_name=None, category=None, small_icon_path=None):
    """
    return a dictionary that represents a feed
    this sets the feed 'metadata' - the description of the feed, and not the feed contents
    this also initializes the reports value
    """

    feed = {}
    feed_info = {}

    feed_info["name"] = feed_name
    feed_info["display_name"] = display_name or feed_name
    feed_info["summary"] = summary
    feed_info["tech_data"] = tech_data
    feed_info["provider_url"] = provider_url

    icon = generate_icon(icon_path)
    if None != icon:
        feed_info["icon"] = icon

    # Add a small icon, if present
    # FEED-129
    if None != small_icon_path:
        small_icon = generate_icon(small_icon_path)
        if None != small_icon:
            feed_info["icon_small"] = small_icon

    # Add a feed category, if present
    # FEED-129
    if None != category:
        feed_info["category"] = category

    feed["feedinfo"] = feed_info
    feed["reports"] = []

    return feed


class FeedSyncRunner(object):
    """
    performs feed synchronization logic
    synchronizes a feed using the provided cb_api reference
    sync_needed should be set to true when a sync is needed
    """
    def __init__(self, cb_api, feed_name, interval=15):
        self.__cb = cb_api
        self.__feed_name = feed_name
        self.__interval = int(interval)
        self.sync_needed = False
        self.sync_supported = False

        if cbint.utils.cbserver.is_server_at_least(self.__cb, "4.1"):
            self.sync_supported = True

        if self.sync_supported:
            sync_thread = threading.Thread(target=self.__perform_feed_sync)
            sync_thread.setDaemon(True)
            sync_thread.start()

    def __perform_feed_sync(self):
        while True:
            time.sleep(self.__interval * 60)

            if self.sync_needed:
                logging.info("synchronizing feed: %s" % self.__feed_name)
                self.__cb.feed_synchronize(self.__feed_name, False)
                self.sync_needed = False
