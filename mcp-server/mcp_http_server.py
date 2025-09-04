#!/usr/bin/env python3
"""
OpenSearch HTTP MCP Server - FastMCP 2.0 Implementation
Provides OpenSearch tools via HTTP with streaming support for large result sets
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, AsyncGenerator, Union

from fastmcp import FastMCP
from pydantic_settings import BaseSettings

# Import OpenSearch client and tools directly
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from mcp_tools import (
    OpenSearchClient
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("opensearch-mcp-http")

class Config(BaseSettings):
    """Server configuration"""
    # OpenSearch
    os_url: str = "https://localhost:9200"
    os_username: str = "admin"
    os_password: str = ""
    os_api_key: Optional[str] = None
    
    # HTTP Server
    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8000
    mcp_path: str = "/mcp"
    
    class Config:
        env_file = ".env"

# Global configuration
config = Config()

# Initialize FastMCP server
mcp = FastMCP("OpenSearch MCP HTTP Server")

# Global OpenSearch client
os_client: Optional[OpenSearchClient] = None

async def initialize_opensearch():
    """Initialize OpenSearch connection"""
    global os_client
    try:
        os_client = OpenSearchClient(
            url=config.os_url,
            username=config.os_username,
            password=config.os_password,
            api_key=config.os_api_key
        )
        
        health = os_client.health_check()
        if health.get("connected"):
            logger.info(f"Connected to OpenSearch: {health.get('cluster_status', 'unknown')} cluster")
        else:
            logger.error(f"Failed to connect to OpenSearch: {health.get('error')}")
            os_client = None
            
    except Exception as e:
        logger.error(f"OpenSearch initialization failed: {e}")
        os_client = None

def ensure_client() -> OpenSearchClient:
    """Ensure OpenSearch client is available"""
    if os_client is None:
        raise ValueError("OpenSearch client not initialized. Please check configuration.")
    return os_client

# =============================================================================
# Basic OpenSearch Tools
# =============================================================================

@mcp.tool
async def list_indices(pattern: str = "*", include_system: bool = False) -> Dict[str, Any]:
    """List OpenSearch indices with metadata"""
    client = ensure_client()
    
    try:
        if not client.client:
            return {"error": "OpenSearch client not initialized"}
            
        indices = client.client.cat.indices(index=pattern, format='json', bytes='b')
        
        if not include_system:
            indices = [idx for idx in indices if not idx.get('index', '').startswith('.')]
        
        result = []
        for idx in indices:
            result.append({
                "index": idx.get('index'),
                "status": idx.get('status'),
                "health": idx.get('health'),
                "doc_count": int(idx.get('docs.count', 0)),
                "store_size_bytes": int(idx.get('store.size', 0)),
                "pri_shards": int(idx.get('pri', 0)),
                "rep_shards": int(idx.get('rep', 0))
            })
        
        return {
            "pattern": pattern,
            "indices": result,
            "total_count": len(result)
        }
    except Exception as e:
        logger.error(f"List indices failed: {e}")
        return {"error": str(e)}


@mcp.tool  
async def execute_sql(query: str, format_type: str = "json") -> Dict[str, Any]:
    """Execute SQL queries against OpenSearch"""
    client = ensure_client()
    
    try:
        if not client.client:
            return {"error": "OpenSearch client not initialized"}
            
        response = client.client.transport.perform_request(
            'POST',
            '/_plugins/_sql',
            body={'query': query, 'format': format_type}
        )
        
        return {
            "query": query,
            "format": format_type,
            "results": response,
            "execution_time_ms": getattr(response, 'took', 0)
        }
    except Exception as e:
        logger.error(f"SQL execution failed: {e}")
        return {"error": str(e), "query": query}


@mcp.tool
async def get_mappings(index_pattern: str = "*") -> Dict[str, Any]:
    """Get field mappings for OpenSearch indices"""
    client = ensure_client()
    
    try:
        if not client.client:
            return {"error": "OpenSearch client not initialized"}
            
        mappings = client.client.indices.get_mapping(index=index_pattern)
        return {
            "index_pattern": index_pattern,
            "mappings": mappings,
            "indices_count": len(mappings)
        }
    except Exception as e:
        logger.error(f"Get mappings failed: {e}")
        return {"error": str(e)}


@mcp.tool
async def search_documents(
    index: str,
    query: Dict[str, Any], 
    size: int = 10,
    from_offset: int = 0,
    fields: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Search OpenSearch documents"""
    client = ensure_client()
    
    try:
        if not client.client:
            return {"error": "OpenSearch client not initialized"}
            
        search_body = {
            "query": query,
            "size": min(size, 1000),  # Limit size to prevent large responses
            "from": from_offset
        }
        
        if fields:
            search_body["_source"] = fields
            
        response = client.client.search(index=index, body=search_body)
        
        return {
            "index": index,
            "total_hits": response['hits']['total']['value'],
            "hits": response['hits']['hits'],
            "took": response.get('took', 0),
            "max_score": response['hits'].get('max_score')
        }
    except Exception as e:
        logger.error(f"Search failed: {e}")
        return {"error": str(e)}


# =============================================================================
# Streaming Tools - For Large Result Sets
# =============================================================================

@mcp.tool
async def search_documents_stream(
    index: str,
    query: Dict[str, Any], 
    size: int = 100,
    batch_size: int = 10,
    fields: Optional[List[str]] = None
) -> AsyncGenerator[Dict[str, Any], None]:
    """Stream search results for large datasets"""
    client = ensure_client()
    
    try:
        if not client.client:
            yield {"error": "OpenSearch client not initialized", "type": "error"}
            return
        
        # Process in batches
        processed = 0
        current_offset = 0
        
        while processed < size:
            current_batch_size = min(batch_size, size - processed)
            
            search_body = {
                "query": query,
                "size": current_batch_size,
                "from": current_offset
            }
            
            if fields:
                search_body["_source"] = fields
                
            response = client.client.search(index=index, body=search_body)
            hits = response['hits']['hits']
            
            if not hits:
                break  # No more results
            
            # Stream each document
            for i, hit in enumerate(hits):
                yield {
                    "type": "document",
                    "data": hit,
                    "metadata": {
                        "index": index,
                        "batch_offset": current_offset,
                        "position_in_batch": i,
                        "total_processed": processed + i + 1,
                        "total_available": response['hits']['total']['value']
                    }
                }
            
            processed += len(hits)
            current_offset += len(hits)
            
            # If we got fewer results than requested, we're done
            if len(hits) < current_batch_size:
                break
                
        yield {
            "type": "summary",
            "data": {
                "total_streamed": processed,
                "query": query,
                "index": index
            }
        }
        
    except Exception as e:
        logger.error(f"Stream search failed: {e}")
        yield {"type": "error", "error": str(e)}


# =============================================================================
# Health Check and Server Info
# =============================================================================

@mcp.tool
def server_status() -> Dict[str, Any]:
    """Get server status information"""
    return {
        "server_name": "OpenSearch MCP HTTP Server",
        "version": "2.0.0", 
        "transport": "HTTP with Streaming",
        "opensearch_connected": os_client is not None,
        "opensearch_status": os_client.health_check() if os_client else None,
        "available_tools": [
            "list_indices", "execute_sql", "get_mappings", 
            "search_documents", "search_documents_stream", "server_status"
        ]
    }


@mcp.custom_route("/health", methods=["GET"])
async def health_check(request):
    """Health check endpoint for monitoring"""
    from starlette.responses import JSONResponse
    
    health_status = {
        "status": "healthy",
        "service": "opensearch-mcp-server",
        "version": "2.0.0",
        "opensearch_connected": os_client is not None
    }
    
    if os_client:
        os_health = os_client.health_check()
        health_status["opensearch_status"] = os_health
    
    return JSONResponse(health_status)


# =============================================================================
# Server Startup and Main
# =============================================================================

async def startup():
    """Initialize server on startup"""
    logger.info("Initializing OpenSearch MCP HTTP Server...")
    await initialize_opensearch()

if __name__ == "__main__":
    # Initialize OpenSearch client
    asyncio.run(startup())
    
    logger.info(f"Starting HTTP MCP Server on {config.mcp_host}:{config.mcp_port}{config.mcp_path}")
    
    # Run HTTP server
    mcp.run(
        transport="http",
        host=config.mcp_host,
        port=config.mcp_port,
        path=config.mcp_path
    )