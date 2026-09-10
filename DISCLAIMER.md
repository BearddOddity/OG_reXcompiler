# Disclaimer

OG_reXcompiler is not affiliated with, authorized by, sponsored by, or endorsed
by Microsoft, Xbox, or any game publisher. It is an independent project created
for educational, preservation, and software-development purposes. All
trademarks, game titles, and copyrights are the property of their respective
owners.

This project ships **no game code, no game assets, and no console firmware**.
It is a source-to-source compiler: you supply a binary you are legally entitled
to use, and it produces C source for that binary. What you do with the result
is your responsibility.

This project is not intended to promote or enable piracy or the unauthorized
use of copyrighted material. Any use of this software to endorse or facilitate
that activity is strictly prohibited.

The software is provided "as is", without warranty of any kind. See `LICENSE`.

## AI assistance

Much of this port was written with AI assistance (Claude / Claude Code). Every
commit produced that way is marked `Co-Authored-By: Claude`. AI-written code can
be wrong in subtle ways; treat this codebase as needing the same review any
machine-translated port needs, and do not assume correctness from the fact that
it compiles or that its tests pass.

## Lineage

OG_reXcompiler is a C# / x86 port of the analysis and code-generation half
(`rex::codegen`) of the **ReXGlue SDK**, retargeted from Xbox 360 / PowerPC to
the original Xbox / 32-bit x86. ReXGlue is itself built on the Xenia project and
credits XenonRecomp and rexdex's recompiler for the static-recompilation
approach. See `CREDITS.md`.
