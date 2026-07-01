package grpc

import (
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"sessionproxy/internal/domain"
	"sessionproxy/internal/pubsub"
	"sessionproxy/internal/transport/grpc/pb"
)

// AdminServer implements pb.AdminServiceServer, streaming
// EnforcementService's pubsub events (blacklist violations, auto-
// terminations) filtered down to links the authenticated caller owns.
// This is the gRPC-native alternative to the dashboard's SSE feed for the
// same events - the same events, a different protocol.
type AdminServer struct {
	pb.UnimplementedAdminServiceServer
	hub   *pubsub.Hub
	links domain.SharedLinkRepository
}

func NewAdminServer(hub *pubsub.Hub, links domain.SharedLinkRepository) *AdminServer {
	return &AdminServer{hub: hub, links: links}
}

func (s *AdminServer) StreamLinkActivity(req *pb.StreamLinkActivityRequest, stream pb.AdminService_StreamLinkActivityServer) error {
	ctx := stream.Context()
	callerID := UserID(ctx)

	var filterLinkID uuid.UUID
	if req.GetLinkId() != "" {
		id, err := uuid.Parse(req.GetLinkId())
		if err != nil {
			return err
		}
		owner, err := s.links.OwnerUserID(ctx, id)
		if err != nil || owner != callerID {
			// Same 404-flavored discretion as REST: do not distinguish
			// "not yours" from "does not exist" over the wire either.
			return nil
		}
		filterLinkID = id
	}

	events, cancel := s.hub.Subscribe()
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return nil
		case evt, ok := <-events:
			if !ok {
				return nil
			}
			if filterLinkID != uuid.Nil && evt.LinkID != filterLinkID {
				continue
			}
			if filterLinkID == uuid.Nil {
				owner, err := s.links.OwnerUserID(ctx, evt.LinkID)
				if err != nil || owner != callerID {
					continue
				}
			}
			if err := stream.Send(toProto(evt)); err != nil {
				return err
			}
		}
	}
}

func toProto(evt pubsub.Event) *pb.LinkActivityEvent {
	t := pb.LinkActivityEventType_LINK_ACTIVITY_EVENT_TYPE_UNSPECIFIED
	switch evt.Type {
	case pubsub.EventBlacklistViolation:
		t = pb.LinkActivityEventType_LINK_ACTIVITY_EVENT_TYPE_BLACKLIST_VIOLATION
	case pubsub.EventLinkTerminated:
		t = pb.LinkActivityEventType_LINK_ACTIVITY_EVENT_TYPE_LINK_TERMINATED
	}
	return &pb.LinkActivityEvent{
		Type:       t,
		LinkId:     evt.LinkID.String(),
		Message:    evt.Message,
		OccurredAt: timestamppb.New(evt.OccurredAt),
	}
}
