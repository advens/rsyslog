.. SPDX-License-Identifier: Apache-2.0

.. _param-mmnormalize-statsname:
.. _mmnormalize.parameter.action.statsname:

.. meta::
   :description: Give an mmnormalize action its own impstats counters.
   :keywords: rsyslog, mmnormalize, statsname, impstats, counters

statsName
=========

.. index::
   single: mmnormalize; statsName
   single: statsName

.. summary-start

Publish per-action parse counters in impstats as ``mmnormalize(<statsName>)``.

.. summary-end

This parameter applies to :doc:`../../configuration/modules/mmnormalize`.

:Name: statsName
:Scope: action
:Type: word
:Default: none
:Required?: no
:Introduced: 8.2612.0

Description
-----------
When set, the action registers an impstats object named
``mmnormalize(<statsName>)`` with origin ``mmnormalize``. Without it the
action publishes nothing of its own and the module-wide ``mmnormalize``
object is unchanged.

The value is 1 to 128 characters of ``[A-Za-z0-9_.-]``, so it can be used
as is in a metric name. Use one name per log source: two actions with the
same name publish two objects with the same name.

Counters:

``parsed``
   A rule matched, with either parser.

``failed``
   No rule matched. ``$parsesuccess`` is ``FAIL``.

``turbo.parsed``
   The TurboVM result was used. Only with ``turbo="on"``.

``turbo.fallback.parsed``
   TurboVM matched no rule and the standard parser did. Only with
   ``turbo="on"``. Both engines run the same rulebase, so this should stay
   at zero: a non-zero value means they disagree on that rulebase, and
   each such message was parsed twice.

``turbo.truncated``
   The TurboVM result was declined because it hit a per-result capacity,
   and the standard parser produced the fields. The module-wide counter of
   the same name counts every action. Only with ``turbo="on"`` and a
   liblognorm that provides ``ln_fast_result_is_truncated()``.

``parsed.<tag>``
   One per entry of :ref:`param-mmnormalize-statstags`.

A failed message costs both parsers when Turbo is on, so ``failed`` is also
a cost signal.

The cost is a relaxed atomic increment per message, on a counter shared by
the action's workers. An action without ``statsName`` pays one predictable
branch.

Action usage
------------
.. _param-mmnormalize-action-statsname:
.. _mmnormalize.parameter.action.statsname-usage:

.. code-block:: rsyslog

   action(type="mmnormalize"
          rulebase="/etc/rsyslog.d/sshd.rb"
          turbo="on"
          statsName="sshd")

See also
--------
See also :doc:`../../configuration/modules/mmnormalize` and
:doc:`../../configuration/modules/impstats`.
