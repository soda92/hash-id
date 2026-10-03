# SPDX-License-Identifier: AGPL-3.0-or-later
# Modernized rewrite of hash-id, originally by Zion3R (www.Blackploit.com).
"""The original startup banner, kept for the interactive prompt."""

from __future__ import annotations

from . import __version__

_LOGO = r"""   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/    \/_____/  \/___/ v{version} #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################"""


def logo() -> str:
    """Return the banner with the current version inserted (``v2.0.0`` style)."""
    return _LOGO.format(version=__version__)
