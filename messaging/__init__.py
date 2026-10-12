"""Messaging & offline-delivery layer: durable storage, sync, unread badges.

The transport-, auth- and E2EE-agnostic store lives here; the server wires it
into the session FSM via the :class:`server.storage.MessageStore` Protocol.
"""