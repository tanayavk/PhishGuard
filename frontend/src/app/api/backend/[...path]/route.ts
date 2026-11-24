import { NextRequest, NextResponse } from "next/server";

const BACKEND_URL =
  process.env.PHISHGUARD_API_URL || "http://127.0.0.1:8000";

async function proxyRequest(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> }
) {
  try {
    const { path } = await context.params;

    const endpoint = path.join("/");
    const url = new URL(
      `${BACKEND_URL}/${endpoint}`
    );

    url.search = request.nextUrl.search;

    const headers = new Headers();

    const contentType = request.headers.get("content-type");

    if (contentType) {
      headers.set("content-type", contentType);
    }

    const apiKey = process.env.PHISHGUARD_API_KEY;

    if (!apiKey) {
      return NextResponse.json(
        { detail: "Backend API key is not configured." },
        { status: 500 }
      );
    }

    headers.set("X-API-Key", apiKey);

    const options: RequestInit = {
      method: request.method,
      headers,
      cache: "no-store",
    };

    if (request.method !== "GET" && request.method !== "HEAD") {
      options.body = await request.arrayBuffer();
    }

    const response = await fetch(url.toString(), options);

    const data = await response.arrayBuffer();

    return new NextResponse(data, {
      status: response.status,
      headers: {
        "Content-Type":
          response.headers.get("content-type") ||
          "application/json",
      },
    });
  } catch (error) {
    console.error("PhishGuard backend proxy error:", error);

    return NextResponse.json(
      {
        detail: "Unable to connect to PhishGuard backend",
        error:
          error instanceof Error ? error.message : "Unknown error",
      },
      { status: 502 }
    );
  }
}

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> }
) {
  return proxyRequest(request, context);
}

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> }
) {
  return proxyRequest(request, context);
}