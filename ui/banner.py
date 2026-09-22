"""
ui/banner.py — Arte ASCII 3D y presentación de LookingTheShark.

Banner se imprime siempre al arrancar lookingtheshark.py, tanto en modo CLI
como en modo menú interactivo. Va antes que cualquier otra salida.
"""

import os
import sys
from rich.console import Console
from rich.align import Align


# ──────────────────────────────────────────────────────
# Versión del framework
# ──────────────────────────────────────────────────────
VERSION = "1.0.0"
AUTOR   = "@nostraxiten"
TAGLINE = "Forensic translator for network captures"
DISCLAIMER_CORTO = "Analyze only own or authorized captures"

# ──────────────────────────────────────────────────────
# Banner ASCII 3D — exacto del spec
# ──────────────────────────────────────────────────────
BANNER_ASCII = r"""
 **         *******     *******   **   **  ******** **      **     **     *******   **   **  ********
/**        **/////**   **/////** /**  **  **////// /**     /**    ****   /**////** /**  **  **////// 
/**       **     //** **     //**/** **  /**       /**     /**   **//**  /**   /** /** **  /**       
/**      /**      /**/**      /**/****   /*********/**********  **  //** /*******  /****   /*********
/**      /**      /**/**      /**/**/**  ////////**/**//////** **********/**///**  /**/**  ////////**
/**      //**     ** //**     ** /**//**        /**/**     /**/**//////**/**  //** /**//**        /**
/******** //*******   //*******  /** //** ******** /**     /**/**     /**/**   //**/** //** ******** 
////////   ///////     ///////   //   // ////////  //      // //      // //     // //   // ////////  
"""

# Versión coloreada ANSI para terminales que soportan color
BANNER_ANSI = (
    "\033[0;36;1m **         *******     *******   **   **  \033[0;97;1m******** **      **     **     *******   **   **  ********\033[0m\n"
    "\033[0;36;1m/**        **/////**   **/////** /**  **  \033[0;97;1m**////// /**     /**    ****   /**////** /**  **  **////// \033[0m\n"
    "\033[0;36;1m/**       **     //** **     //**/** **  \033[0;97;1m/**       /**     /**   **//**  /**   /** /** **  /**       \033[0m\n"
    "\033[0;36;1m/**      /**      /**/**      /**/****   \033[0;97;1m/*********/**********  **  //** /*******  /****   /*********\033[0m\n"
    "\033[0;36;1m/**      /**      /**/**      /**/**/**  \033[0;97;1m////////**/**//////** **********/**///**  /**/**  ////////**\033[0m\n"
    "\033[0;36;1m/**      //**     ** //**     ** /**//** \033[0;97;1m       /**/**     /**/**//////**/**  //** /**//**        /**\033[0m\n"
    "\033[0;36;1m/******** //*******   //*******  /** //**\033[0;97;1m ******** /**     /**/**     /**/**   //**/** //** ********\033[0m\n"
    "\033[0;36;1m////////   ///////     ///////   //   // \033[0;97;1m////////  //      // //      // //     // //   // ////////  \033[0m\n"
)


def _soporte_ansi() -> bool:
    """Detecta si el terminal soporta secuencias ANSI."""
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
            return True
        except Exception:
            return False
    return os.environ.get("TERM", "") != "dumb"


def mostrar_banner(console: Console) -> None:
    """Muestra el banner completo de LookingTheShark en el terminal."""
    console.print()

    if _soporte_ansi():
        sys.stdout.write(BANNER_ANSI)
        sys.stdout.flush()
    else:
        console.print(BANNER_ASCII, style="bold cyan")

    # ── Línea de versión + disclaimer ──────────────────
    console.print()
    console.print(
        Align.center(
            f"[bold cyan]LookingTheShark[/] [dim]v{VERSION}[/]  [color(240)]|[/]  "
            f"[bold white]{TAGLINE}[/]"
        )
    )
    console.print(
        Align.center(
            f"[dim]{DISCLAIMER_CORTO}[/]"
        )
    )
    console.print(
        Align.center(f"[dim]by {AUTOR}[/]")
    )
    console.print()
    console.print(Align.center("[color(240)]" + "═" * 55 + "[/]"))
    console.print()
