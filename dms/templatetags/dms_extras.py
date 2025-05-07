from django import template
import os

register = template.Library()

@register.filter
def filename(value):
    """Returns the filename part of a file path"""
    return os.path.basename(value)

@register.filter
def split_tags(value):
    """Splits a comma-separated string of tags"""
    if not value:
        return []
    return [tag.strip() for tag in value.split(',')]