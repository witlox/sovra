#!/usr/bin/env bash
#
# build-docker.sh - Build Docker images locally
#
# This script builds Docker images for Sovra services with
# proper tagging and multi-architecture support.
#
# Usage:
#   ./scripts/build-docker.sh [options]
#
# Options:
#   --push        Push images to registry
#   --platform    Target platform (default: linux/amd64)
#   --tag         Image tag (default: latest)
#   --registry    Registry prefix (default: ghcr.io/witlox)
#
set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Default values
PUSH=false
PLATFORM="linux/amd64"
TAG="latest"
REGISTRY="ghcr.io/witlox"
PROJECT_NAME="sovra"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --push)
            PUSH=true
            shift
            ;;
        --platform)
            PLATFORM="$2"
            shift 2
            ;;
        --tag)
            TAG="$2"
            shift 2
            ;;
        --registry)
            REGISTRY="$2"
            shift 2
            ;;
        --help|-h)
            head -n 16 "$0" | tail -n 12 | sed 's/^#//'
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Get version from git
get_version() {
    if git describe --tags --exact-match 2>/dev/null; then
        return
    fi
    
    local latest_tag
    latest_tag=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
    local commit_hash
    commit_hash=$(git rev-parse --short HEAD)
    echo "${latest_tag}-${commit_hash}"
}

VERSION=$(get_version)
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(git rev-parse HEAD)

log_info "Building Sovra Docker images"
log_info "  Version: $VERSION"
log_info "  Tag: $TAG"
log_info "  Platform: $PLATFORM"
log_info "  Registry: $REGISTRY"
echo ""

# Check if Dockerfile exists
if [[ ! -f "Dockerfile" ]]; then
    log_warn "Dockerfile not found, using default build"
fi

# Build image
build_image() {
    local image_name="${REGISTRY}/${PROJECT_NAME}:${TAG}"
    local version_tag="${REGISTRY}/${PROJECT_NAME}:${VERSION}"
    
    log_info "Building image: $image_name"
    
    docker build \
        --platform "$PLATFORM" \
        --build-arg VERSION="$VERSION" \
        --build-arg BUILD_DATE="$BUILD_DATE" \
        --build-arg GIT_COMMIT="$GIT_COMMIT" \
        --tag "$image_name" \
        --tag "$version_tag" \
        .
    
    log_info "Built: $image_name"
    log_info "Built: $version_tag"
    
    if [[ "$PUSH" == "true" ]]; then
        log_info "Pushing images..."
        docker push "$image_name"
        docker push "$version_tag"
        log_info "Pushed successfully"
    fi
}

# Build multi-arch if requested
build_multiarch() {
    local image_name="${REGISTRY}/${PROJECT_NAME}:${TAG}"
    local version_tag="${REGISTRY}/${PROJECT_NAME}:${VERSION}"
    
    log_info "Building multi-architecture image..."
    
    # Ensure buildx is available
    if ! docker buildx version &> /dev/null; then
        log_warn "docker buildx not available, falling back to single-arch"
        build_image
        return
    fi
    
    # Create builder if needed
    if ! docker buildx inspect sovra-builder &> /dev/null; then
        docker buildx create --name sovra-builder --use
    fi
    
    local push_flag=""
    if [[ "$PUSH" == "true" ]]; then
        push_flag="--push"
    else
        push_flag="--load"
    fi
    
    docker buildx build \
        --platform linux/amd64,linux/arm64 \
        --build-arg VERSION="$VERSION" \
        --build-arg BUILD_DATE="$BUILD_DATE" \
        --build-arg GIT_COMMIT="$GIT_COMMIT" \
        --tag "$image_name" \
        --tag "$version_tag" \
        $push_flag \
        .
    
    log_info "Multi-arch build complete"
}

# Main
main() {
    if [[ "$PLATFORM" == "linux/amd64,linux/arm64" ]] || [[ "$PLATFORM" == "multi" ]]; then
        PLATFORM="linux/amd64,linux/arm64"
        build_multiarch
    else
        build_image
    fi
    
    echo ""
    log_info "========================================="
    log_info "Docker build complete!"
    log_info "========================================="
    echo ""
    echo "Image: ${REGISTRY}/${PROJECT_NAME}:${TAG}"
    echo "Version: ${VERSION}"
    echo ""
    
    if [[ "$PUSH" == "false" ]]; then
        echo "To push: $0 --push --tag $TAG"
    fi
}

main
