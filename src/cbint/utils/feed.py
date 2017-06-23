import base64

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
