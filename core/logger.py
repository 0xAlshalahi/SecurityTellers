"""Colored logging utility."""


class Logger:
    def __init__(self, verbose=False, no_color=False):
        self.verbose = verbose
        self.no_color = no_color

    def _c(self, code, text):
        if self.no_color:
            return text
        return f"\033[{code}m{text}\033[0m"

    def info(self, msg):
        print(f"  {self._c('96', '[*]')} {msg}")

    def success(self, msg):
        print(f"  {self._c('92', '[+]')} {msg}")

    def warn(self, msg):
        print(f"  {self._c('93', '[!]')} {msg}")

    def error(self, msg):
        print(f"  {self._c('91', '[-]')} {msg}")

    def debug(self, msg):
        if self.verbose:
            print(f"  {self._c('90', '[D]')} {msg}")

    def found(self, msg):
        print(f"  {self._c('92', ' ↳')} {msg}")

    def section(self, title):
        bar = "─" * 50
        print(f"\n  {self._c('91', bar)}")
        print(f"  {self._c('91;1', f'  {title}')}")
        print(f"  {self._c('91', bar)}")
