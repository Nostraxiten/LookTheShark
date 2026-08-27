"""
ui/banner.py — Presentacion de arranque.

El banner grande se muestra si la terminal es lo bastante ancha; si no, cae a
una version compacta. En Windows se activa antes el soporte de secuencias ANSI
para que no aparezcan codigos de escape sueltos en cmd.exe.
"""

from __future__ import annotations

import os
import shutil
import sys

from rich.align import Align
from rich.console import Console

VERSION = "2.0.0"
AUTOR = "@nostraxiten"
TAGLINE = "Traductor forense de capturas de red"
DISCLAIMER = "Analiza solo capturas propias o autorizadas"

BANNER_ANCHO = r"""
 **         *******     *******   **   **  ******** **      **     **     *******   **   **  ********
/**        **/////**   **/////** /**  **  **////// /**     /**    ****   /**////** /**  **  **//////
/**       **     //** **     //**/** **  /**       /**     /**   **//**  /**   /** /** **  /**
/**      /**      /**/**      /**/****   /*********/**********  **  //** /*******  /****   /*********
/**      /**      /**/**      /**/**/**  ////////**/**//////** **********/**///**  /**/**  ////////**
/**      //**     ** //**     ** /**//**        /**/**     /**/**//////**/**  //** /**//**        /**
/******** //*******   //*******  /** //** ******** /**     /**/**     /**/**   //**/** //** ********
////////   ///////     ///////   //   // ////////  //      // //      // //     // //   // ////////
"""

BANNER_COMPACTO = r"""
  __             _   _______        ______        __
 / /  ___  ___  / /__/_  __/ /  ___ / __/ /  ___ _/ /__
/ /__/ _ \/ _ \/  '_/ / / / _ \/ -_)\ \/ _ \/ _ `/ __/
\___/\___/\___/_/\_\ /_/ /_//_/\__/___/_//_/\_,_/_/\__/
"""

_ANCHO_MINIMO = 104


def _activar_ansi_windows() -> bool:
    """Habilita las secuencias de escape en consolas de Windows antiguas."""
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        for handle_id in (-11, -12):          # STDOUT y STDERR
            handle = kernel32.GetStdHandle(handle_id)
            modo = ctypes.c_ulong()
            if kernel32.GetConsoleMode(handle, ctypes.byref(modo)):
                # ENABLE_VIRTUAL_TERMINAL_PROCESSING
                kernel32.SetConsoleMode(handle, modo.value | 0x0004)
        return True
    except Exception:
        return False


def soporta_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if sys.platform == "win32":
        return _activar_ansi_windows()
    return os.environ.get("TERM", "") not in ("", "dumb")


def _ancho_terminal() -> int:
    try:
        return shutil.get_terminal_size(fallback=(80, 24)).columns
    except OSError:
        return 80


def mostrar_banner(console: Console, compacto: bool = False) -> None:
    """Imprime el banner adaptado al ancho disponible."""
    console.print()

    # console.width respeta un ancho fijado a mano; si no, se mira la terminal.
    ancho = getattr(console, "width", 0) or _ancho_terminal()
    arte = BANNER_COMPACTO if (compacto or ancho < _ANCHO_MINIMO) else BANNER_ANCHO

    for i, linea in enumerate(arte.strip("\n").split("\n")):
        # Degradado del cian de la marca al blanco, de arriba a abajo.
        tono = ["color(45)", "color(45)", "color(51)", "color(51)",
                "color(87)", "color(87)", "color(123)", "color(159)"][i % 8]
        console.print(f"[{tono}]{linea}[/]", highlight=False)

    console.print()
    console.print(Align.center(
        f"[marca]LookingTheShark[/] [dim_text]v{VERSION}[/]  "
        f"[separador]│[/]  [titulo]{TAGLINE}[/]"), highlight=False)
    console.print(Align.center(f"[dim_text]{DISCLAIMER} · por {AUTOR}[/]"),
                  highlight=False)
    console.print()
    console.print("[separador]" + "─" * min(ancho - 2, 78) + "[/]")
    console.print()
