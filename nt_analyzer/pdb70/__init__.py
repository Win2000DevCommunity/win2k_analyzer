"""PDB 7.0 (MSF 7.00 / DS) support — separate from PDB 2.0 kernel path."""

from nt_analyzer.pdb70.msf import detect_pdb_format, parse_msf70

__all__ = ['detect_pdb_format', 'parse_msf70', 'SymbolUpdater70']


def __getattr__(name):
    if name == 'SymbolUpdater70':
        from nt_analyzer.pdb70.updater import SymbolUpdater70
        return SymbolUpdater70
    raise AttributeError(name)
