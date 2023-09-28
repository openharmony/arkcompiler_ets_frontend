# Eclipse JDT Core libraries
Eclipse JDT Core is the core part of Eclipse Java Development Tools platform (JDT). It includes:

- An incremental Java compiler. Implemented as an Eclipse builder, it is based on technology evolved from VisualAge for Java compiler. In particular, it allows to run and debug code which still contains unresolved errors.
- A Java Model that provides API for navigating the Java element tree. The Java element tree defines a Java centric view of a project. It surfaces elements like package fragments, compilation units, binary classes, types, methods, fields. 
- A Java Document Model providing API for manipulating a structured Java source document.
- Code assist and code select support.
- An indexed based search infrastructure that is used for searching, code assist, type hierarchy computation, and refactoring. The Java search engine can accurately find precise matches either in sources or binaries.
- Evaluation support either in a scrapbook page or a debugger context.
- Source code formatter

**Official website:** http://www.eclipse.org/jdt/core/index.php

# Version
Versions of libraries are selected based on the requirement for migrator project to be compatible 
with Java 8. They may be updated in the future.

# License
All libraries except **org.eclipse.core.resources-3.12.0.jar** are distributed under 
[Eclipse Public License (EPL), version 2.0](http://www.eclipse.org/legal/epl-2.0/). 
The library **org.eclipse.core.resources-3.12.0.jar** is distributed under 
[Eclipse Public License (EPL), version 1.0](http://www.eclipse.org/legal/epl-v10.html).

# Artifacts
The artifacts for these libraries are downloaded from the following URLs:

- https://repo1.maven.org/maven2/org/eclipse/jdt/org.eclipse.jdt.core/3.20.0/
- https://repo1.maven.org/maven2/org/eclipse/platform/org.eclipse.core.commands/3.10.0/
- https://repo1.maven.org/maven2/org/eclipse/platform/org.eclipse.core.contenttype/3.7.1000/
- https://repo1.maven.org/maven2/org/eclipse/platform/org.eclipse.core.expressions/3.7.100/
- https://repo1.maven.org/maven2/org/eclipse/platform/org.eclipse.core.filesystem/1.9.0/
- https://repo1.maven.org/maven2/org/eclipse/platform/org.eclipse.core.jobs/3.11.0/
- https://repo1.maven.org/maven2/org/eclipse/platform/org.eclipse.core.resources/3.12.0/
- https://repo1.maven.org/maven2/org/eclipse/platform/org.eclipse.core.runtime/3.17.100/
- https://repo1.maven.org/maven2/org/eclipse/platform/org.eclipse.equinox.app/1.5.100/
- https://repo1.maven.org/maven2/org/eclipse/platform/org.eclipse.equinox.common/3.11.0/
- https://repo1.maven.org/maven2/org/eclipse/platform/org.eclipse.equinox.preferences/3.8.200/
- https://repo1.maven.org/maven2/org/eclipse/platform/org.eclipse.equinox.registry/3.10.200/
- https://repo1.maven.org/maven2/org/eclipse/platform/org.eclipse.osgi/3.16.300/
- https://repo1.maven.org/maven2/org/eclipse/platform/org.eclipse.text/3.12.0/
