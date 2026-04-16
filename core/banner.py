"""ASCII banner for SecurityTellers."""

VERSION = "1.0.0"

def print_banner():
    R = "\033[91m"
    W = "\033[97m"
    C = "\033[96m"
    D = "\033[90m"
    N = "\033[0m"

    print(f"""{R}
   ____                       _ __       ______     ____
  / __/__ ______ _____(_) /___ __/_  ___/ / / /__ _______
 _\ \/ -_) __/ // / __/ / __/ // / / / -_) / / -_) __(_-<
/___/\__/\__/\_,_/_/ /_/\__/\_, /  \__/\__/_/_/\__/_/ /___/
                           /___/
{W}  Domain & IP Intelligence Gathering Framework  {D}v{VERSION}{N}
{C}  Author: Abdulelah Al-shalahi (@0xAlshalahi){N}
""")
