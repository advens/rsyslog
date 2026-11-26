.. SPDX-License-Identifier: Apache-2.0

.. _param-mmnormalize-statstags:
.. _mmnormalize.parameter.action.statstags:

.. meta::
   :description: Count TurboVM matches by rule tag in the per-action impstats object.
   :keywords: rsyslog, mmnormalize, statstags, impstats, tags

statsTags
=========

.. index::
   single: mmnormalize; statsTags
   single: statsTags

.. summary-start

Count TurboVM matches whose rule carries one of these tags, as
``parsed.<tag>``.

.. summary-end

This parameter applies to :doc:`../../configuration/modules/mmnormalize`.

:Name: statsTags
:Scope: action
:Type: array of words
:Default: none
:Required?: no
:Introduced: 8.2612.0

Description
-----------
Each entry adds a counter ``parsed.<tag>`` to the object that
:ref:`param-mmnormalize-statsname` creates. A message is counted when the
rule that matched it carries that tag (``rule=<tag>,...:``). It requires
``statsName``. At most 8 tags; each is 1 to 64 characters of
``[A-Za-z0-9_.-]`` and appears once.

A typical use is a rule that accepts any line, kept so that unknown
messages still reach storage. ``$parsesuccess`` is ``OK`` for those
lines, so ``failed`` does not show them. Tagging such rules and listing
the tag here shows how much traffic only a catch-all rule matched.

Tags are read from the TurboVM result, without building JSON. A message
parsed by the standard parser instead (see ``turbo.fallback.parsed`` and
``turbo.truncated``) is not counted here.

Action usage
------------
.. _param-mmnormalize-action-statstags:
.. _mmnormalize.parameter.action.statstags-usage:

.. code-block:: rsyslog

   action(type="mmnormalize"
          rulebase="/etc/rsyslog.d/sshd.rb"
          turbo="on"
          statsName="sshd"
          statsTags=["catchall"])

See also
--------
See also :doc:`../../configuration/modules/mmnormalize`.
