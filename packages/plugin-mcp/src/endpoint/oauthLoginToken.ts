import type { PayloadRequest, SanitizedCollectionConfig } from 'payload'

import { randomUUID } from 'crypto'
import { APIError, getFieldsToSign, jwtSign } from 'payload'
import { removeExpiredSessions } from 'payload/shared'

import type { MCPOAuthTokens } from '../types.js'

/** How long a refresh token stays valid without being used, in milliseconds: 30 days. */
const refreshTokenExpiration = 30 * 24 * 60 * 60 * 1000

/**
 * How long a used refresh token is still accepted, in milliseconds. MCP clients that send
 * requests in parallel can refresh twice at once with the same refresh token.
 */
const refreshTokenReuseInterval = 30 * 1000

type User = NonNullable<PayloadRequest['user']>

type Session = NonNullable<User['sessions']>[number]

/** The default refresh token. The OAuth server seals it, so clients can't read or change it. */
type LoginRefreshToken = {
  collection: string
  /** The session's `expiresAt` when this refresh token was issued. Every refresh moves it. */
  expiresAt: number
  sid: string
  userID: number | string
}

/**
 * The default `issueToken`: a Payload login token, which Payload's JWT strategy accepts. When the
 * collection uses sessions, the token gets its own login session, and the client gets a refresh
 * token for it.
 */
export const issueLoginToken = async ({
  req,
}: {
  req: PayloadRequest
}): Promise<MCPOAuthTokens> => {
  const collection = req.payload.collections[req.user!.collection]!.config

  if (collection.auth.disableLocalStrategy) {
    throw new APIError(
      `MCP clients can't get Payload login tokens for the "${collection.slug}" collection because its local strategy is disabled. Pass oauth.issueToken to the MCP plugin.`,
    )
  }

  const user = (await findUser({ id: req.user!.id, collection, req }))!

  if (!collection.auth.useSessions) {
    return await signLoginToken({ collection, req, user })
  }

  const session = await saveSession({ collection, req, sid: randomUUID(), user })

  return await signLoginToken({ collection, req, session, user })
}

/**
 * The default `refreshToken`. Every refresh moves the session's expiry, so a refresh token with an
 * older expiry was already used. Outside of parallel refreshes, that means someone copied it, and
 * the session is signed out, which also revokes the client's access token.
 */
export const refreshLoginToken = async ({
  refreshToken,
  req,
}: {
  refreshToken: string
  req: PayloadRequest
}): Promise<MCPOAuthTokens | null> => {
  const { collection: slug, expiresAt, sid, userID } = JSON.parse(refreshToken) as LoginRefreshToken
  const collection = req.payload.collections[slug]?.config
  const user = collection && (await findUser({ id: userID, collection, req }))
  const session = removeExpiredSessions(user?.sessions ?? []).find(({ id }) => id === sid)

  // Signed out, expired, or the user was deleted
  if (!collection || !user || !session) {
    return null
  }

  const sessionExpiresAt = new Date(session.expiresAt).getTime()

  if (sessionExpiresAt === expiresAt) {
    return await signLoginToken({
      collection,
      req,
      session: await saveSession({ collection, req, sid, user }),
      user,
    })
  }

  // The client refreshed twice at once, so give the second request the current tokens
  const refreshedAt = sessionExpiresAt - refreshTokenExpiration

  if (Date.now() - refreshedAt < refreshTokenReuseInterval) {
    return await signLoginToken({ collection, req, session, user })
  }

  // Someone copied the refresh token
  await saveSessions({
    collection,
    req,
    sessions: user.sessions!.filter(({ id }) => id !== sid),
    user,
  })

  return null
}

// The full document, like the one a password login starts its session on
const findUser = ({
  id,
  collection,
  req,
}: {
  collection: SanitizedCollectionConfig
  id: number | string
  req: PayloadRequest
}): Promise<null | User> =>
  req.payload.db.findOne<User>({ collection: collection.slug, req, where: { id: { equals: id } } })

/** Adds or extends the session `sid`, so it expires `refreshTokenExpiration` from now. */
const saveSession = async ({
  collection,
  req,
  sid,
  user,
}: {
  collection: SanitizedCollectionConfig
  req: PayloadRequest
  sid: string
  user: User
}): Promise<Session> => {
  const now = new Date()
  const session: Session = {
    id: sid,
    createdAt: user.sessions?.find(({ id }) => id === sid)?.createdAt ?? now,
    expiresAt: new Date(now.getTime() + refreshTokenExpiration),
  }

  await saveSessions({
    collection,
    req,
    sessions: [
      ...removeExpiredSessions(user.sessions ?? []).filter(({ id }) => id !== sid),
      session,
    ],
    user,
  })

  return session
}

const saveSessions = async ({
  collection,
  req,
  sessions,
  user,
}: {
  collection: SanitizedCollectionConfig
  req: PayloadRequest
  sessions: Session[]
  user: User
}): Promise<void> => {
  await req.payload.db.updateOne({
    id: user.id,
    collection: collection.slug,
    // Prevent updatedAt from being updated when only changing sessions
    data: { ...user, sessions, updatedAt: null },
    req,
    returning: false,
  })
}

const signLoginToken = async ({
  collection,
  req,
  session,
  user,
}: {
  collection: SanitizedCollectionConfig
  req: PayloadRequest
  session?: Session
  user: User
}): Promise<MCPOAuthTokens> => {
  const { token } = await jwtSign({
    fieldsToSign: getFieldsToSign({
      collectionConfig: collection,
      email: user.email!,
      sid: session?.id,
      user,
    }),
    secret: req.payload.secret,
    tokenExpiration: collection.auth.tokenExpiration,
  })

  return {
    accessToken: token,
    expiresIn: collection.auth.tokenExpiration,
    refreshToken:
      session &&
      JSON.stringify({
        collection: collection.slug,
        expiresAt: new Date(session.expiresAt).getTime(),
        sid: session.id,
        userID: user.id,
      } satisfies LoginRefreshToken),
  }
}
