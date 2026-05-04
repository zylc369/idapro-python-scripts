import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

function getContentTypeFromHeader(value: string | null): string | null {
  if (value === null) {
    return null
  }

  const normalized = value.trim()
  if (!normalized || normalized.length > 120 || /[\r\n]/.test(normalized)) {
    return null
  }

  const match = normalized.match(
    /^([a-zA-Z0-9!#$&^_.+-]+\/[a-zA-Z0-9!#$&^_.+-]+)(?:\s*;\s*charset=(.+))?$/,
  )

  if (!match) {
    return null
  }

  const charset = match[2]
  return charset ? `text/html; charset=${charset}` : 'text/html; charset=utf-8'
}

export function middleware(request: NextRequest) {
  if (request.nextUrl.searchParams.size > 0) {
    const cleanUrl = request.nextUrl.clone()
    cleanUrl.search = ''
    return NextResponse.redirect(cleanUrl)
  }

  const requestHeaders = new Headers(request.headers)
  const response = NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  })

  const contentType = getContentTypeFromHeader(request.headers.get('content-type'))
  if (contentType) {
    response.headers.set('Content-Type', contentType)
  }

  return response
}

// Config to ensure middleware only runs on necessary paths
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes, though we might want it on /api too, leaving default usually excludes /api but we can include all)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
}
